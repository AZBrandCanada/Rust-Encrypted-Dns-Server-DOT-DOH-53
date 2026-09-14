// src/engine.rs
use crate::cache::{now_secs, CacheEntry, DnsCache};
use crate::dnssec::{DnssecStatus, DnssecValidator};
use crate::ratelimit::{RateLimiter, RrlAction};
use crate::recursor::{calculate_min_ttl, RecursiveResolver};
use dashmap::DashMap;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone)]
pub struct AppState {
    pub cache: DnsCache,
    pub recursor: Arc<RecursiveResolver>,
    pub rate_limiter: Arc<RateLimiter>,
    pub dnssec_enforce: bool,
    pub in_flight: Arc<DashMap<String, ()>>,
}

fn is_cacheable(msg: &Message) -> bool {
    matches!(msg.response_code(), ResponseCode::NoError | ResponseCode::NXDomain)
}

pub async fn process_dns_wire(
    req_wire: &[u8],
    state: &AppState,
    protocol: &'static str,
    client_ip: IpAddr,
) -> Vec<u8> {
    let start = Instant::now();
    let mut decoder = BinDecoder::new(req_wire);
    let req_msg = match Message::read(&mut decoder) {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };

    let query = match req_msg.queries().first() {
        Some(q) => q,
        None => return make_servfail_wire(req_msg.id(), None),
    };

    let qname = query.name().clone();
    let qtype = query.query_type();

    let (client_max_payload, client_dnssec_ok) = match req_msg.extensions().as_ref() {
        Some(e) => (
            (e.max_payload() as usize).clamp(512, 1232),
            e.flags().dnssec_ok,
        ),
        None => (512, false),
    };

    match state.rate_limiter.check_query(protocol, client_ip, &qname, qtype) {
        RrlAction::Allow => {}
        RrlAction::Truncate => {
            tracing::warn!(
                protocol,
                client = %client_ip,
                domain = %qname,
                rtype = %qtype,
                "[SECURITY] Challenging client with TC=1"
            );
            return make_truncated_wire(req_msg.id(), Some(query));
        }
        RrlAction::Drop => {
            tracing::warn!(
                protocol,
                client = %client_ip,
                domain = %qname,
                rtype = %qtype,
                "[SECURITY] Rate limit dropped"
            );
            return Vec::new();
        }
    }

    let cache_key = format!(
        "{}:{}:IN:do={}",
        qname.to_ascii().to_lowercase(),
        qtype,
        if client_dnssec_ok { 1 } else { 0 }
    );
    let now = now_secs();

    // ---------------------------------------------------------------------
    // 1. Cache hit path
    // ---------------------------------------------------------------------
    if let Some(entry) = state.cache.get(&cache_key) {
        let age = now.saturating_sub(entry.cached_at);
        let is_stale = age >= entry.min_ttl as u64;

        if is_stale {
            if state.in_flight.insert(cache_key.clone(), ()).is_none() {
                let cache_clone = state.cache.clone();
                let recursor_clone = state.recursor.clone();
                let key_clone = cache_key.clone();
                let name_clone = qname.clone();
                let in_flight_clone = state.in_flight.clone();

                tokio::spawn(async move {
                    if let Ok(mut fresh_msg) =
                        recursor_clone.resolve(&name_clone, qtype).await
                    {
                        // Validate the fresh response.  For a signed zone,
                        // this either confirms AD=1 (Secure), clears AD
                        // (Insecure / unsigned zone), or rejects the
                        // response entirely (Bogus).  Negative responses
                        // (NXDOMAIN / NODATA) go through the NSEC/NSEC3
                        // proof path via validate_message.
                        let status = DnssecValidator::validate_message(
                            &recursor_clone,
                            &fresh_msg,
                            &name_clone,
                            qtype,
                        )
                        .await;

                        match status {
                            DnssecStatus::Secure => {
                                fresh_msg.set_authentic_data(true);
                            }
                            DnssecStatus::Insecure => {
                                fresh_msg.set_authentic_data(false);
                            }
                            DnssecStatus::Bogus => {
                                // Do NOT overwrite a previously-good cache
                                // entry with a Bogus verdict from a fresh
                                // resolution.  The upstream we hit may be
                                // under attack, misconfigured, or simply
                                // flaky; keeping the old entry bounds the
                                // blast radius of a transient failure and
                                // prevents a race-winner from poisoning
                                // a name we already had correct.
                                tracing::warn!(
                                    domain = %name_clone,
                                    rtype = %qtype,
                                    "[DNSSEC] Bogus response during stale \
                                     revalidation; keeping previous cache entry"
                                );
                                in_flight_clone.remove(&key_clone);
                                return;
                            }
                        }

                        if is_cacheable(&fresh_msg) {
                            if let Ok(wire) = fresh_msg.to_bytes() {
                                let ttl = calculate_min_ttl(&fresh_msg);
                                let cur_time = now_secs();
                                cache_clone.insert(
                                    key_clone.clone(),
                                    CacheEntry {
                                        raw_wire: wire,
                                        min_ttl: ttl,
                                        cached_at: cur_time,
                                        last_revalidated_at: cur_time,
                                    },
                                );
                            }
                        } else if let Some(mut existing) =
                            cache_clone.get_mut(&key_clone)
                        {
                            existing.last_revalidated_at = now_secs();
                        }
                    }
                    in_flight_clone.remove(&key_clone);
                });
            }
        }

        if state.rate_limiter.should_challenge_large_response(
            protocol,
            client_ip,
            entry.raw_wire.len(),
            client_max_payload,
        ) {
            return make_truncated_wire(req_msg.id(), Some(query));
        }

        let mut wire = entry.raw_wire.clone();
        if wire.len() >= 2 && req_wire.len() >= 2 {
            wire[0] = req_wire[0];
            wire[1] = req_wire[1];
        }
        return wire;
    }

    // ---------------------------------------------------------------------
    // 2. Cache miss path
    // ---------------------------------------------------------------------
    match state.recursor.resolve(&qname, qtype).await {
        Ok(mut resp_msg) => {
            // Validate the full message.  This dispatches on whether the
            // answer section is empty:
            //
            //   * Positive answers  -> RRSIG on the RRset, chain to root.
            //   * NXDOMAIN / NODATA -> NSEC or NSEC3 denial-of-existence
            //                          proof validated against the zone
            //                          keys.
            //
            // Prior to this change, negative responses skipped validation
            // entirely: a forged NXDOMAIN from an on-path attacker (or a
            // compromised authoritative server) was accepted and cached.
            let dnssec_status = DnssecValidator::validate_message(
                &state.recursor,
                &resp_msg,
                &qname,
                qtype,
            )
            .await;

            match dnssec_status {
                DnssecStatus::Secure => {
                    resp_msg.set_authentic_data(true);
                }
                DnssecStatus::Insecure => {
                    resp_msg.set_authentic_data(false);
                }
                DnssecStatus::Bogus => {
                    if state.dnssec_enforce {
                        tracing::warn!(
                            protocol,
                            client = %client_ip,
                            domain = %qname,
                            rtype = %qtype,
                            "[DNSSEC] Bogus DNSSEC proof (positive or \
                             negative); returning SERVFAIL"
                        );
                        return make_servfail_wire(req_msg.id(), Some(query));
                    }
                    // Enforcement disabled: surface the answer but
                    // explicitly downgrade the AD bit so downstream
                    // validators know we did not confirm it.
                    resp_msg.set_authentic_data(false);
                }
            }

            resp_msg.set_id(req_msg.id());
            let wire = match resp_msg.to_bytes() {
                Ok(w) => w,
                Err(_) => return make_servfail_wire(req_msg.id(), Some(query)),
            };

            if is_cacheable(&resp_msg) {
                let ttl = calculate_min_ttl(&resp_msg);
                state.cache.insert(
                    cache_key,
                    CacheEntry {
                        raw_wire: wire.clone(),
                        min_ttl: ttl,
                        cached_at: now,
                        last_revalidated_at: now,
                    },
                );
            }

            tracing::info!(
                protocol,
                client = %client_ip,
                domain = %qname,
                rtype = %qtype,
                latency_ms = start.elapsed().as_millis(),
                "[RESOLVED] Resolution completed"
            );

            if state.rate_limiter.should_challenge_large_response(
                protocol,
                client_ip,
                wire.len(),
                client_max_payload,
            ) {
                return make_truncated_wire(req_msg.id(), Some(query));
            }

            wire
        }
        Err(err) => {
            tracing::error!(
                protocol,
                client = %client_ip,
                domain = %qname,
                rtype = %qtype,
                error = %err,
                "[ERROR] Recursive resolution failed; returning SERVFAIL"
            );
            make_servfail_wire(req_msg.id(), Some(query))
        }
    }
}

pub fn make_truncated_wire(id: u16, query: Option<&hickory_proto::op::Query>) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Response);
    msg.set_truncated(true);
    msg.set_recursion_available(true);
    if let Some(q) = query {
        msg.add_query(q.clone());
    }
    msg.to_bytes().unwrap_or_default()
}

pub fn make_servfail_wire(id: u16, query: Option<&hickory_proto::op::Query>) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Response);
    msg.set_response_code(ResponseCode::ServFail);
    if let Some(q) = query {
        msg.add_query(q.clone());
    }
    msg.to_bytes().unwrap_or_default()
}