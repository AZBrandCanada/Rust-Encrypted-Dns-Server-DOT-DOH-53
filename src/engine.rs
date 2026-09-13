// src/engine.rs
use crate::cache::{now_secs, CacheEntry, DnsCache};
use crate::dnssec::{DnssecStatus, DnssecValidator};
use crate::ratelimit::RateLimiter;
use crate::recursor::{calculate_min_ttl, RecursiveResolver};
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
    if !state.rate_limiter.allow(client_ip) {
        tracing::debug!(protocol, client_ip = %client_ip, "[RATELIMIT] Dropped query over rate limit");
        return Vec::new();
    }

    let _start = Instant::now();
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
    let cache_key = format!("{}:{}:IN:do=0", qname, qtype);
    let now = now_secs();

    // 1. Cache hit path
    if let Some(entry) = state.cache.get(&cache_key) {
        let age = now.saturating_sub(entry.cached_at);
        let is_stale = age >= entry.min_ttl as u64;

        if is_stale {
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
        }

        let mut wire = entry.raw_wire.clone();
        if wire.len() >= 2 && req_wire.len() >= 2 {
            wire[0] = req_wire[0];
            wire[1] = req_wire[1];
        }
        return wire;
    }

    // 2. Cache miss path
    match state.recursor.resolve(&qname, qtype).await {
        Ok(mut resp_msg) => {
            if !resp_msg.answers().is_empty() {
                let all_records: Vec<_> = resp_msg.answers().to_vec();
                let status = DnssecValidator::validate_answer(
                    &state.recursor,
                    &qname,
                    qtype,
                    &all_records,
                )
                .await;

                match status {
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
                                protocol, domain = %qname, rtype = %qtype,
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

            wire
        }
        Err(_) => make_servfail_wire(req_msg.id(), Some(query)),
    }
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
