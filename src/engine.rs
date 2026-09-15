use crate::cache::{now_secs, CacheEntry, CacheFreshness, DnsCache, STALE_SERVE_TTL};
use crate::dnssec::{DnssecStatus, DnssecValidator};
use crate::ratelimit::{RateLimiter, RrlAction};
use crate::recursor::{calculate_min_ttl, RecursiveResolver};
use dashmap::DashMap;
use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::op::{Edns, Message, MessageType, ResponseCode};
use hickory_proto::rr::{RData, RecordType};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessOutcome {
    Success(Vec<u8>),
    ServFail(Vec<u8>),
    Truncated(Vec<u8>),
    Dropped,
    Malformed,
}

impl ProcessOutcome {
    pub fn into_wire(self) -> Vec<u8> {
        match self {
            ProcessOutcome::Success(wire)
            | ProcessOutcome::ServFail(wire)
            | ProcessOutcome::Truncated(wire) => wire,
            ProcessOutcome::Dropped | ProcessOutcome::Malformed => Vec::new(),
        }
    }
}

fn is_cacheable(msg: &Message) -> bool {
    matches!(msg.response_code(), ResponseCode::NoError | ResponseCode::NXDomain)
}

fn is_cacheable_dnssec(status: DnssecStatus) -> bool {
    matches!(
        status,
        DnssecStatus::Secure | DnssecStatus::InsecureUnsigned
    )
}

fn is_dnssec_record(rtype: RecordType) -> bool {
    matches!(
        rtype,
        RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
    )
}

/// RFC 4035 §5.3.3: Binds the cached TTL of a Secure RRset to the remaining validity
/// period of its participating RRSIGs using RFC 1982 serial number arithmetic.
pub fn remaining_rrsig_validity(msg: &Message, now: u64) -> Option<u32> {
    let now32 = (now & 0xFFFF_FFFF) as u32;
    let mut min_remaining = u32::MAX;

    for r in msg.answers().iter().chain(msg.name_servers().iter()) {
        if let RData::DNSSEC(DNSSECRData::RRSIG(sig)) = r.data() {
            let exp = sig.sig_expiration().get();
            let diff = exp.wrapping_sub(now32) as i32;
            if diff > 0 {
                min_remaining = min_remaining.min(diff as u32);
            } else {
                return Some(0);
            }
        }
    }

    if min_remaining == u32::MAX {
        None
    } else {
        Some(min_remaining)
    }
}

fn construct_client_response(
    base_msg: &Message,
    qtype: RecordType,
    dnssec_status: DnssecStatus,
    freshness: CacheFreshness,
    cached_at: u64,
    req_msg: &Message,
    client_max_payload: usize,
    client_dnssec_ok: bool,
    now: u64,
) -> Option<Vec<u8>> {
    let mut client_resp = Message::new();

    client_resp.set_id(req_msg.id());
    client_resp.set_message_type(MessageType::Response);
    client_resp.set_op_code(req_msg.op_code());
    client_resp.set_authoritative(false);
    client_resp.set_truncated(false);
    client_resp.set_recursion_available(true);
    client_resp.set_recursion_desired(req_msg.recursion_desired());
    client_resp.set_checking_disabled(req_msg.checking_disabled());
    client_resp.set_response_code(base_msg.response_code());

    for q in req_msg.queries() {
        client_resp.add_query(q.clone());
    }

    // RFC 4035 §3.2.2/3, RFC 6840 §5.7/8, RFC 8767 §6:
    // AD is asserted iff Secure, fresh, client signaled interest, and CD=0.
    let client_wants_ad = client_dnssec_ok || req_msg.authentic_data();
    let client_cd = req_msg.checking_disabled();

    let ad = dnssec_status == DnssecStatus::Secure
        && freshness == CacheFreshness::Fresh
        && client_wants_ad
        && !client_cd;

    client_resp.set_authentic_data(ad);

    let age = now.saturating_sub(cached_at) as u32;

    let compute_ttl = |orig_ttl: u32| -> u32 {
        match freshness {
            CacheFreshness::Fresh => orig_ttl.saturating_sub(age),
            CacheFreshness::Stale => STALE_SERVE_TTL,
            CacheFreshness::Expired => 0,
        }
    };

    for r in base_msg.answers() {
        if !client_dnssec_ok && is_dnssec_record(r.record_type()) && r.record_type() != qtype {
            continue;
        }
        let mut rec = r.clone();
        rec.set_ttl(compute_ttl(rec.ttl()));
        client_resp.add_answer(rec);
    }

    for r in base_msg.name_servers() {
        if !client_dnssec_ok && is_dnssec_record(r.record_type()) && r.record_type() != qtype {
            continue;
        }
        let mut rec = r.clone();
        rec.set_ttl(compute_ttl(rec.ttl()));
        client_resp.add_name_server(rec);
    }

    for r in base_msg.additionals() {
        if r.record_type() == RecordType::OPT {
            continue;
        }
        if !client_dnssec_ok && is_dnssec_record(r.record_type()) && r.record_type() != qtype {
            continue;
        }
        let mut rec = r.clone();
        rec.set_ttl(compute_ttl(rec.ttl()));
        client_resp.add_additional(rec);
    }

    if req_msg.extensions().is_some() {
        let mut edns = Edns::new();
        edns.set_max_payload(client_max_payload as u16);
        edns.set_dnssec_ok(client_dnssec_ok);
        edns.set_version(0);
        client_resp.set_edns(edns);
    }

    client_resp.to_bytes().ok()
}

pub async fn process_dns_query(
    req_wire: &[u8],
    state: &AppState,
    protocol: &'static str,
    client_ip: IpAddr,
) -> ProcessOutcome {
    let start = Instant::now();
    let mut decoder = BinDecoder::new(req_wire);
    let req_msg = match Message::read(&mut decoder) {
        Ok(m) => m,
        Err(_) => return ProcessOutcome::Malformed,
    };

    if req_msg.queries().len() != 1 {
        tracing::debug!(
            protocol,
            client = %client_ip,
            query_count = req_msg.queries().len(),
            "[DNS] Request does not contain exactly one question; rejecting as Malformed"
        );
        return ProcessOutcome::Malformed;
    }

    let query = &req_msg.queries()[0];
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
            return ProcessOutcome::Truncated(make_truncated_wire(req_msg.id(), Some(query)));
        }
        RrlAction::Drop => {
            tracing::warn!(
                protocol,
                client = %client_ip,
                domain = %qname,
                rtype = %qtype,
                "[SECURITY] Rate limit dropped"
            );
            return ProcessOutcome::Dropped;
        }
    }

    let cache_key = format!("{}:{}:IN", qname.to_ascii().to_lowercase(), qtype);
    let now = now_secs();

    if let Some(entry) = state.cache.get(&cache_key) {
        let freshness = entry.freshness(now);

        if freshness != CacheFreshness::Expired {
            if freshness == CacheFreshness::Stale {
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
                                DnssecStatus::InsecureUnsigned | DnssecStatus::InsecureUnknown => {
                                    fresh_msg.set_authentic_data(false);
                                }
                                DnssecStatus::Bogus => {
                                    tracing::warn!(
                                        domain = %name_clone,
                                        rtype = %qtype,
                                        "[DNSSEC] Bogus response during stale revalidation; keeping previous cache entry"
                                    );
                                    in_flight_clone.remove(&key_clone);
                                    return;
                                }
                            }

                            if is_cacheable(&fresh_msg) && is_cacheable_dnssec(status) {
                                fresh_msg.set_authoritative(false);
                                fresh_msg.set_recursion_available(true);
                                if let Ok(wire) = fresh_msg.to_bytes() {
                                    let mut ttl = calculate_min_ttl(&fresh_msg);
                                    let cur_time = now_secs();

                                    // RFC 4035 §5.3.3: Bound TTL to remaining signature validity
                                    if status == DnssecStatus::Secure {
                                        if let Some(rrsig_ttl) = remaining_rrsig_validity(&fresh_msg, cur_time) {
                                            ttl = ttl.min(rrsig_ttl);
                                        }
                                    }

                                    cache_clone.insert(
                                        key_clone.clone(),
                                        CacheEntry {
                                            raw_wire: wire,
                                            min_ttl: ttl,
                                            cached_at: cur_time,
                                            last_revalidated_at: cur_time,
                                            dnssec_status: status,
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

            let mut decoder = BinDecoder::new(&entry.raw_wire);
            if let Ok(cached_msg) = Message::read(&mut decoder) {
                let cached_status = entry.dnssec_status;

                if let Some(wire) = construct_client_response(
                    &cached_msg,
                    qtype,
                    cached_status,
                    freshness,
                    entry.cached_at,
                    &req_msg,
                    client_max_payload,
                    client_dnssec_ok,
                    now,
                ) {
                    if state.rate_limiter.should_challenge_large_response(
                        protocol,
                        client_ip,
                        wire.len(),
                        client_max_payload,
                    ) {
                        return ProcessOutcome::Truncated(make_truncated_wire(req_msg.id(), Some(query)));
                    }

                    return ProcessOutcome::Success(wire);
                }
            }
        }
    }

    match state.recursor.resolve(&qname, qtype).await {
        Ok(mut resp_msg) => {
            let dnssec_status = DnssecValidator::validate_message(
                &state.recursor,
                &resp_msg,
                &qname,
                qtype,
            )
            .await;

            let client_cd = req_msg.checking_disabled();

            match dnssec_status {
                DnssecStatus::Bogus if state.dnssec_enforce && !client_cd => {
                    tracing::warn!(
                        protocol,
                        client = %client_ip,
                        domain = %qname,
                        rtype = %qtype,
                        "[DNSSEC] Bogus DNSSEC proof; returning SERVFAIL"
                    );
                    return ProcessOutcome::ServFail(make_servfail_wire(req_msg.id(), Some(query)));
                }
                DnssecStatus::Bogus if client_cd => {
                    tracing::debug!(
                        protocol,
                        client = %client_ip,
                        domain = %qname,
                        rtype = %qtype,
                        "[DNSSEC] Bogus proof but client set CD=1; serving with AD=0"
                    );
                }
                DnssecStatus::Bogus => {
                    tracing::warn!(
                        protocol,
                        client = %client_ip,
                        domain = %qname,
                        rtype = %qtype,
                        "[DNSSEC] Bogus DNSSEC proof; enforcement disabled, serving with AD=0"
                    );
                }
                _ => {}
            }

            resp_msg.set_authentic_data(dnssec_status == DnssecStatus::Secure);
            resp_msg.set_authoritative(false);
            resp_msg.set_recursion_available(true);

            if is_cacheable(&resp_msg) && is_cacheable_dnssec(dnssec_status) {
                if let Ok(canonical_wire) = resp_msg.to_bytes() {
                    let mut ttl = calculate_min_ttl(&resp_msg);

                    // RFC 4035 §5.3.3: Bound TTL to remaining signature validity
                    if dnssec_status == DnssecStatus::Secure {
                        if let Some(rrsig_ttl) = remaining_rrsig_validity(&resp_msg, now) {
                            ttl = ttl.min(rrsig_ttl);
                        }
                    }

                    state.cache.insert(
                        cache_key,
                        CacheEntry {
                            raw_wire: canonical_wire,
                            min_ttl: ttl,
                            cached_at: now,
                            last_revalidated_at: now,
                            dnssec_status,
                        },
                    );
                }
            } else if dnssec_status == DnssecStatus::InsecureUnknown {
                tracing::debug!(
                    protocol,
                    client = %client_ip,
                    domain = %qname,
                    rtype = %qtype,
                    "[DNSSEC] InsecureUnknown verdict; serving without caching"
                );
            }

            let wire = match construct_client_response(
                &resp_msg,
                qtype,
                dnssec_status,
                CacheFreshness::Fresh,
                now,
                &req_msg,
                client_max_payload,
                client_dnssec_ok,
                now,
            ) {
                Some(w) => w,
                None => return ProcessOutcome::ServFail(make_servfail_wire(req_msg.id(), Some(query))),
            };

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
                return ProcessOutcome::Truncated(make_truncated_wire(req_msg.id(), Some(query)));
            }

            ProcessOutcome::Success(wire)
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
            ProcessOutcome::ServFail(make_servfail_wire(req_msg.id(), Some(query)))
        }
    }
}

pub async fn process_dns_wire(
    req_wire: &[u8],
    state: &AppState,
    protocol: &'static str,
    client_ip: IpAddr,
) -> Vec<u8> {
    process_dns_query(req_wire, state, protocol, client_ip)
        .await
        .into_wire()
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