// src/engine.rs
use crate::cache::{now_secs, CacheEntry, DnsCache};
use crate::recursor::{calculate_min_ttl, RecursiveResolver};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable};
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone)]
pub struct AppState {
    pub cache: DnsCache,
    pub recursor: Arc<RecursiveResolver>,
}

/// Whether a resolved message is worth caching. This now includes
/// NODATA (NOERROR with zero answers — e.g. an AAAA query against an
/// IPv4-only host) in addition to real answers and NXDOMAIN. Skipping
/// NODATA was the single biggest cause of "every lookup is slow": every
/// OS/browser fires off A *and* AAAA queries for essentially every
/// hostname, and any AAAA-less site was re-walked from the root on
/// every request, forever.
fn is_cacheable(msg: &Message) -> bool {
    matches!(msg.response_code(), ResponseCode::NoError | ResponseCode::NXDomain)
}

pub async fn process_dns_wire(req_wire: &[u8], state: &AppState, protocol: &'static str) -> Vec<u8> {
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
    let cache_key = format!("{}:{}:IN:do=0", qname, qtype);
    let now = now_secs();

    tracing::debug!(
        protocol = protocol,
        id = req_msg.id(),
        domain = %qname,
        rtype = %qtype,
        "[QUERY] DNS query received"
    );

    // 1. Cache hit path (covers positive answers, NXDOMAIN, and NODATA).
    if let Some(entry) = state.cache.get(&cache_key) {
        let age = now.saturating_sub(entry.cached_at);
        let is_stale = age >= entry.min_ttl as u64;

        if is_stale {
            tracing::debug!(
                protocol = protocol,
                domain = %qname,
                rtype = %qtype,
                age_secs = age,
                ttl = entry.min_ttl,
                "[STALE] Serving stale cache; spawning background revalidation"
            );

            let cache_clone = state.cache.clone();
            let recursor_clone = state.recursor.clone();
            let key_clone = cache_key.clone();
            let name_clone = qname.clone();

            tokio::spawn(async move {
                if let Ok(fresh_msg) = recursor_clone.resolve(&name_clone, qtype).await {
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
            tracing::debug!(
                protocol = protocol,
                domain = %qname,
                rtype = %qtype,
                latency_us = start.elapsed().as_micros(),
                "[HIT] In-memory cache hit"
            );
        }

        let mut wire = entry.raw_wire.clone();
        if wire.len() >= 2 && req_wire.len() >= 2 {
            wire[0] = req_wire[0];
            wire[1] = req_wire[1];
        }
        return wire;
    }

    // 2. Cache miss path.
    tracing::debug!(
        protocol = protocol,
        domain = %qname,
        rtype = %qtype,
        "[MISS] Cache miss; starting recursive resolution"
    );

    match state.recursor.resolve(&qname, qtype).await {
        Ok(mut resp_msg) => {
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
                protocol = protocol,
                domain = %qname,
                rtype = %qtype,
                rcode = %rcode,
                answers = answers_count,
                latency_ms = start.elapsed().as_millis(),
                "[RESOLVED] Resolution completed"
            );

            wire
        }
        Err(err) => {
            tracing::warn!(
                protocol = protocol,
                domain = %qname,
                rtype = %qtype,
                error = %err,
                latency_ms = start.elapsed().as_millis(),
                "[ERROR] Resolution failed; returning SERVFAIL"
            );
            make_servfail_wire(req_msg.id(), Some(query))
        }
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
