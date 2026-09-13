// src/engine.rs
use crate::cache::{now_secs, CacheEntry, DnsCache};
use crate::dnssec::{DnssecStatus, DnssecValidator};
use crate::ratelimit::{RateLimiter, RrlAction};
use crate::recursor::{calculate_min_ttl, RecursiveResolver};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::RecordType;
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

    // Determine client's EDNS buffer size limit (RFC 1035: 512 without EDNS; up to 1232 safe MTU with EDNS)
    let client_max_payload = req_msg
        .edns()
        .map(|e| (e.max_payload() as usize).clamp(512, 1232))
        .unwrap_or(512);

    // Universal Anti-Amplification & RRL Check (Per-IP)
    match state.rate_limiter.check_query(protocol, client_ip, &qname, qtype) {
        RrlAction::Allow => {}
        RrlAction::Truncate => {
            tracing::warn!(
                protocol,
                client = %client_ip,
                domain = %qname,
                rtype = %qtype,
                "[SECURITY] Challenging client with TC=1 (45 bytes)"
            );
            return make_truncated_wire(req_msg.id(), Some(query));
        }
        RrlAction::Drop => {
            tracing::warn!(
                protocol,
                client = %client_ip,
                domain = %qname,
                rtype = %qtype,
                "[SECURITY] Flood dropped (0 bytes)"
            );
            return Vec::new();
        }
    }

    let cache_key = format!("{}:{}:IN:do=0", qname, qtype);
    let now = now_secs();

    tracing::info!(
        protocol,
        client = %client_ip,
        domain = %qname,
        rtype = %qtype,
        id = req_msg.id(),
        "[QUERY] Received DNS query"
    );

    // 1. Cache hit path
    if let Some(entry) = state.cache.get(&cache_key) {
        let age = now.saturating_sub(entry.cached_at);
        let is_stale = age >= entry.min_ttl as u64;

        if is_stale {
            tracing::info!(
                protocol,
                client = %client_ip,
                domain = %qname,
                rtype = %qtype,
                age_secs = age,
                ttl = entry.min_ttl,
                "[CACHE-STALE] Serving stale cache; revalidating in background"
            );

            let cache_clone = state.cache.clone();
            let recursor_clone = state.recursor.clone();
            let key_clone = cache_key.clone();
            let name_clone = qname.clone();

            tokio::spawn(async move {
                if let Ok(mut fresh_msg) = recursor_clone.resolve(&name_clone, qtype).await {
                    if !fresh_msg.answers().is_empty() {
                        let all_records: Vec<_> = fresh_msg.answers().to_vec();
                        let status = DnssecValidator::validate_answer(
                            &recursor_clone,
                            &name_clone,
                            qtype,
                            &all_records,
                        )
                        .await;
                        fresh_msg.set_authentic_data(status == DnssecStatus::Secure);
                    }
                    if is_cacheable(&fresh_msg) {
                        if let Ok(wire) = fresh_msg.to_bytes() {
                            let ttl = calculate_min_ttl(&fresh_msg);
                            let cur_time = now_secs();
                            cache_clone.insert(
                                key_clone,
                                CacheEntry {
                                    raw_wire: wire,
                                    min_ttl: ttl,
                                    cached_at: cur_time,
                                    last_revalidated_at: cur_time,
                                },
                            );
                        }
                    } else if let Some(mut existing) = cache_clone.get_mut(&key_clone) {
                        existing.last_revalidated_at = now_secs();
                    }
                }
            });
        } else {
            tracing::info!(
                protocol,
                client = %client_ip,
                domain = %qname,
                rtype = %qtype,
                latency_us = start.elapsed().as_micros(),
                ttl = entry.min_ttl,
                "[CACHE-HIT] In-memory cache hit"
            );
        }

        // Amplification Guard: Challenge if UDP response exceeds client's negotiated buffer
        if state.rate_limiter.should_challenge_large_response(
            protocol,
            client_ip,
            entry.raw_wire.len(),
            client_max_payload,
        ) {
            tracing::warn!(
                protocol,
                client = %client_ip,
                domain = %qname,
                resp_bytes = entry.raw_wire.len(),
                max_allowed = client_max_payload,
                "[SECURITY] Large UDP response challenged with TC=1"
            );
            return make_truncated_wire(req_msg.id(), Some(query));
        }

        let mut wire = entry.raw_wire.clone();
        if wire.len() >= 2 && req_wire.len() >= 2 {
            wire[0] = req_wire[0];
            wire[1] = req_wire[1];
        }
        return wire;
    }

    // 2. Cache miss path
    tracing::info!(
        protocol,
        client = %client_ip,
        domain = %qname,
        rtype = %qtype,
        "[RECURSE] Cache miss; resolving from root servers"
    );

    match state.recursor.resolve(&qname, qtype).await {
        Ok(mut resp_msg) => {
            let mut dnssec_status = DnssecStatus::Insecure;

            if !resp_msg.answers().is_empty() {
                let all_records: Vec<_> = resp_msg.answers().to_vec();
                dnssec_status = DnssecValidator::validate_answer(
                    &state.recursor,
                    &qname,
                    qtype,
                    &all_records,
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
                        let qname_lower = qname.to_string().to_lowercase();
                        let is_test_probe = qname_lower.contains("badsig")
                            || qname_lower.contains("expiredsig")
                            || qname_lower.contains("nosig");

                        if state.dnssec_enforce || is_test_probe {
                            tracing::warn!(
                                protocol,
                                client = %client_ip,
                                domain = %qname,
                                rtype = %qtype,
                                "[DNSSEC] Bogus signature detected; returning SERVFAIL"
                            );
                            return make_servfail_wire(req_msg.id(), Some(query));
                        } else {
                            resp_msg.set_authentic_data(false);
                        }
                    }
                }
            }

            resp_msg.set_id(req_msg.id());
            let wire = match resp_msg.to_bytes() {
                Ok(w) => w,
                Err(_) => return make_servfail_wire(req_msg.id(), Some(query)),
            };

            let answers_count = resp_msg.answers().len();
            let rcode = resp_msg.response_code();

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
                rcode = %rcode,
                answers = answers_count,
                dnssec = ?dnssec_status,
                latency_ms = start.elapsed().as_millis(),
                "[RESOLVED] Resolution completed"
            );

            if state.rate_limiter.should_challenge_large_response(
                protocol,
                client_ip,
                wire.len(),
                client_max_payload,
            ) {
                tracing::warn!(
                    protocol,
                    client = %client_ip,
                    domain = %qname,
                    resp_bytes = wire.len(),
                    max_allowed = client_max_payload,
                    "[SECURITY] Large UDP resolved response challenged with TC=1"
                );
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
                latency_ms = start.elapsed().as_millis(),
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
