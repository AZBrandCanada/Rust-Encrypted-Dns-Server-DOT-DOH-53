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

/// Normalize the flags on a fresh response Message destined for a recursive
/// client:
///   * AA must be cleared (we are not authoritative)
///   * RA must be set (we do offer recursion)
///   * RD must echo the client's RD
///   * CD must echo the client's CD
///   * AD is set by the caller based on the DNSSEC verdict
fn normalize_response_flags(resp: &mut Message, req: &Message, ad: bool) {
    resp.set_authoritative(false);
    resp.set_recursion_available(true);
    resp.set_recursion_desired(req.recursion_desired());
    resp.set_checking_disabled(req.checking_disabled());
    resp.set_authentic_data(ad);
}

/// Rewrite the flags of an already-encoded wire response so that it is
/// suitable for the given client.  Preserves RCODE and the resolver's AD
/// verdict; clears AA; sets RA; echoes RD and CD from the request; rewrites
/// the transaction ID.
fn normalize_cached_wire(wire: &mut [u8], req_wire: &[u8]) {
    if wire.len() < 4 || req_wire.len() < 4 {
        return;
    }
    // Transaction ID
    wire[0] = req_wire[0];
    wire[1] = req_wire[1];

    let client_flags = u16::from_be_bytes([req_wire[2], req_wire[3]]);
    let mut flags = u16::from_be_bytes([wire[2], wire[3]]);

    flags &= !0x0400;                                     // clear AA  (bit 10)
    flags |= 0x0080;                                      // set RA    (bit 7)
    flags = (flags & !0x0100) | (client_flags & 0x0100);  // echo RD   (bit 8)
    flags = (flags & !0x0010) | (client_flags & 0x0010);  // echo CD   (bit 4)

    wire[2] = (flags >> 8) as u8;
    wire[3] = (flags & 0xff) as u8;
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
                            // Normalize flags before caching, so that
                            // every cache read serves a correctly shaped
                            // response.
                            fresh_msg.set_authoritative(false);
                            fresh_msg.set_recursion_available(true);
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
        normalize_cached_wire(&mut wire, req_wire);
        return wire;
    }

    // ---------------------------------------------------------------------
    // 2. Cache miss path
    // ---------------------------------------------------------------------
    match state.recursor.resolve(&qname, qtype).await {
        Ok(mut resp_msg) => {
            let dnssec_status = DnssecValidator::validate_message(
                &state.recursor,
                &resp_msg,
                &qname,
                qtype,
            )
            .await;

            let ad = match dnssec_status {
                DnssecStatus::Secure => true,
                DnssecStatus::Insecure => false,
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
                    tracing::warn!(
                        protocol,
                        client = %client_ip,
                        domain = %qname,
                        rtype = %qtype,
                        "[DNSSEC] Bogus DNSSEC proof; enforcement disabled, \
                         serving with AD=0"
                    );
                    false
                }
            };

            // Normalize the response for the client BEFORE we cache or
            // return it.  This clears the upstream AA bit, sets RA, and
            // echoes RD/CD from the client request.
            normalize_response_flags(&mut resp_msg, &req_msg, ad);
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
    msg.set_authoritative(false);
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
    msg.set_recursion_available(true);
    msg.set_authoritative(false);
    if let Some(q) = query {
        msg.add_query(q.clone());
    }
    msg.to_bytes().unwrap_or_default()
}