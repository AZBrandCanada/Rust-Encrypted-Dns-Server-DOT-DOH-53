use crate::cache::{now_secs, CacheEntry, CacheFreshness, DnsCache};
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

/// Differentiated processing outcome for upstream protocols (DoH, DoT, UDP, TCP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessOutcome {
    /// Successfully produced a standard DNS response wire buffer.
    Success(Vec<u8>),
    /// Valid query produced a DNS-level SERVFAIL response wire buffer.
    ServFail(Vec<u8>),
    /// Truncated response challenge (TC=1) for TCP retry or payload amplification mitigation.
    Truncated(Vec<u8>),
    /// Query dropped intentionally (e.g. rate-limiting or ANY drop).
    Dropped,
    /// Malformed or unparseable input wire buffer (DoH translates to HTTP 400 Bad Request).
    Malformed,
}

impl ProcessOutcome {
    /// Converts the outcome into wire format for transport layers that only handle raw bytes.
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

/// Constructs a client-tailored DNS response from a canonical validated message.
///
/// Implements the unified response construction pipeline:
/// 1. Injects client Transaction ID and echoes RD/CD flags.
/// 2. Sets authoritative=false and recursion_available=true.
/// 3. Computes the AD bit strictly per RFC 4035 §3.2.2/§3.2.3, RFC 6840 §5.7/§5.8, and RFC 8767 §6:
///    - Requires DnssecStatus::Secure.
///    - Requires fresh data (stale cache hits MUST NOT set AD).
///    - Requires unexpired signatures.
///    - Requires client signaling interest via DO=1 or request AD=1.
///    - Requires Checking Disabled to be clear (CD=0).
/// 4. Decrements all Resource Record TTLs according to elapsed age (RFC 2181), skipping OPT.
/// 5. Filters DNSSEC records (RRSIG, NSEC, NSEC3) if client DO=0 (RFC 4035 §3.2.1),
///    unless the client explicitly queried for that specific record type.
/// 6. Adds or suppresses the EDNS0 OPT record depending on whether the client sent EDNS.
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

    // 1. Transaction ID and base header flags
    client_resp.set_id(req_msg.id());
    client_resp.set_message_type(MessageType::Response);
    client_resp.set_op_code(req_msg.op_code());
    client_resp.set_authoritative(false);
    client_resp.set_truncated(false);
    client_resp.set_recursion_available(true);
    client_resp.set_recursion_desired(req_msg.recursion_desired());
    client_resp.set_checking_disabled(req_msg.checking_disabled());
    client_resp.set_response_code(base_msg.response_code());

    // Echo query section
    for q in req_msg.queries() {
        client_resp.add_query(q.clone());
    }

    // 2. AD bit determination
    // Check if any RRSIG in the response has surpassed its cryptographic expiration
    let any_rrsig_expired = base_msg
        .answers()
        .iter()
        .chain(base_msg.name_servers().iter())
        .any(|r| {
            if let RData::DNSSEC(DNSSECRData::RRSIG(sig)) = r.data() {
                (sig.sig_expiration().get() as u64) < now
            } else {
                false
            }
        });

    // RFC 6840 §5.7 & §5.8: The client signals interest in AD either via EDNS DO=1
    // or by setting the AD bit in the request header. If neither was set, AD MUST NOT be set.
    let client_wants_ad = client_dnssec_ok || req_msg.authentic_data();

    // RFC 4035 §3.2.2: A query with CD=1 indicates checking disabled; the resolver
    // MUST NOT assert AD=1 in the response.
    let client_cd = req_msg.checking_disabled();

    // RFC 4035 §3.2.3 / RFC 6840 §5.7 & §5.8: AD set iff fully validated Secure,
    // client asked/signaled interest, CD is clear, and signatures are current.
    // RFC 8767 §6: Responses served from stale cache MUST NOT set AD.
    let ad = dnssec_status == DnssecStatus::Secure
        && freshness == CacheFreshness::Fresh
        && !any_rrsig_expired
        && client_wants_ad
        && !client_cd;

    client_resp.set_authentic_data(ad);

    // 3. TTL aging and DO=0 presentation filtering
    let age = now.saturating_sub(cached_at) as u32;

    // Answers section
    for r in base_msg.answers() {
        // RFC 4035 §3.2.1: Strip DNSSEC RRs if DO=0 unless explicitly requested
        if !client_dnssec_ok && is_dnssec_record(r.record_type()) && r.record_type() != qtype {
            continue;
        }
        let mut rec = r.clone();
        rec.set_ttl(rec.ttl().saturating_sub(age));
        client_resp.add_answer(rec);
    }

    // Authority (Name Servers) section
    for r in base_msg.name_servers() {
        if !client_dnssec_ok && is_dnssec_record(r.record_type()) && r.record_type() != qtype {
            continue;
        }
        let mut rec = r.clone();
        rec.set_ttl(rec.ttl().saturating_sub(age));
        client_resp.add_name_server(rec);
    }

    // Additionals section (excluding OPT, which is managed via set_edns below)
    for r in base_msg.additionals() {
        if r.record_type() == RecordType::OPT {
            continue;
        }
        if !client_dnssec_ok && is_dnssec_record(r.record_type()) && r.record_type() != qtype {
            continue;
        }
        let mut rec = r.clone();
        rec.set_ttl(rec.ttl().saturating_sub(age));
        client_resp.add_additional(rec);
    }

    // 4. EDNS0 (OPT) handling (RFC 6891 §6.1.1)
    // Only return an OPT record if the client sent an OPT record in the request
    if req_msg.extensions().is_some() {
        let mut edns = Edns::new();
        edns.set_max_payload(client_max_payload as u16);
        edns.set_dnssec_ok(client_dnssec_ok);
        edns.set_version(0);
        client_resp.set_edns(edns);
    }

    client_resp.to_bytes().ok()
}

/// Detailed query processing pipeline returning a typed `ProcessOutcome`.
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

    // RFC 1035 §4.1.2 & RFC 8906 §3.2: Standard DNS requires exactly one question.
    // If the request contains 0 or more than 1 question, reject as Malformed.
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

    // Rate Limiting check
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

    // Canonical, client-agnostic cache key
    let cache_key = format!("{}:{}:IN", qname.to_ascii().to_lowercase(), qtype);
    let now = now_secs();

    // ---------------------------------------------------------------------
    // 1. Cache hit path
    // ---------------------------------------------------------------------
    if let Some(entry) = state.cache.get(&cache_key) {
        let freshness = entry.freshness(now);

        // Do not serve Expired records; fall through to synchronous resolution
        if freshness != CacheFreshness::Expired {
            // Stale-While-Revalidate: serve stale while triggering background revalidation
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

            let mut decoder = BinDecoder::new(&entry.raw_wire);
            if let Ok(cached_msg) = Message::read(&mut decoder) {
                let cached_status = if cached_msg.authentic_data() {
                    DnssecStatus::Secure
                } else {
                    DnssecStatus::InsecureUnsigned
                };

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

    // ---------------------------------------------------------------------
    // 2. Cache miss path (or Expired stale fallback)
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

            // Persist the canonical response into cache if cacheable
            resp_msg.set_authentic_data(dnssec_status == DnssecStatus::Secure);
            resp_msg.set_authoritative(false);
            resp_msg.set_recursion_available(true);

            if is_cacheable(&resp_msg) && is_cacheable_dnssec(dnssec_status) {
                if let Ok(canonical_wire) = resp_msg.to_bytes() {
                    let ttl = calculate_min_ttl(&resp_msg);
                    state.cache.insert(
                        cache_key,
                        CacheEntry {
                            raw_wire: canonical_wire,
                            min_ttl: ttl,
                            cached_at: now,
                            last_revalidated_at: now,
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

            // Reconstruct client-tailored response
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

/// Standard entrypoint maintaining backward compatibility across all socket listeners.
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