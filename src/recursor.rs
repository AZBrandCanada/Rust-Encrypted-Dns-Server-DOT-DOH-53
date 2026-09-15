use dashmap::DashMap;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::CNAME;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};
use rand::seq::SliceRandom;
use rand::Rng;
use std::collections::HashSet;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::cache::now_secs;

pub const ROOT_SERVERS: &[&str] = &[
    "198.41.0.4",     // a.root-servers.net
    "199.9.14.201",   // b.root-servers.net
    "192.33.4.12",    // c.root-servers.net
    "199.7.91.13",    // d.root-servers.net
    "192.203.230.10", // e.root-servers.net
    "192.5.5.241",    // f.root-servers.net
    "192.112.36.4",   // g.root-servers.net
    "198.97.190.53",  // h.root-servers.net
    "192.36.148.17",  // i.root-servers.net
    "192.58.128.30",  // j.root-servers.net
    "193.0.14.129",   // k.root-servers.net
    "199.7.83.42",    // l.root-servers.net
    "202.12.27.33",   // m.root-servers.net
];

const QUERY_TIMEOUT: Duration = Duration::from_millis(2000);
const TCP_TIMEOUT: Duration = Duration::from_millis(2500);
const MAX_DEPTH: usize = 16;
const MAX_STEPS: usize = 16;
const MIN_DELEGATION_TTL: u64 = 300;
const MAX_DELEGATION_TTL: u64 = 172_800;

pub const DNAME_RECORD_TYPE: RecordType = RecordType::Unknown(39);

#[derive(Debug, Error)]
pub enum RecursorError {
    #[error("Maximum recursion depth exceeded")]
    DepthExceeded,
    #[error("Maximum resolution steps exceeded")]
    StepLimitExceeded,
    #[error("All nameservers timed out or failed to respond")]
    AllNameserversFailed,
    #[error("Failed to resolve nameserver glue IP")]
    GlueResolutionFailed,
    #[error("Delegation made no forward progress or loop detected")]
    NoProgress,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("DNS Protocol error: {0}")]
    Proto(#[from] hickory_proto::ProtoError),
    #[error("DNS Decode error: {0}")]
    Decode(#[from] hickory_proto::serialize::binary::DecodeError),
}

struct DelegationEntry {
    servers: Vec<IpAddr>,
    expires_at: u64,
}

pub struct RecursiveResolver {
    delegation_cache: DashMap<String, DelegationEntry>,
}

/// Robust DNS message decoder that handles buggy authoritative servers (e.g. dnsleaktest.com).
/// If decoding fails and the packet contains records in the Additional section, it retries
/// with ARCOUNT=0 to salvage the valid Answer and Authority sections.
fn decode_response(buf: &[u8]) -> Result<Message, hickory_proto::ProtoError> {
    let mut decoder = BinDecoder::new(buf);
    match Message::read(&mut decoder) {
        Ok(msg) => Ok(msg),
        Err(e) => {
            if buf.len() >= 12 {
                let arcount = u16::from_be_bytes([buf[10], buf[11]]);
                if arcount > 0 {
                    let mut sanitized = buf.to_vec();
                    sanitized[10] = 0;
                    sanitized[11] = 0;
                    let mut second_decoder = BinDecoder::new(&sanitized);
                    if let Ok(salvaged) = Message::read(&mut second_decoder) {
                        tracing::debug!(
                            arcount,
                            "[RECURSOR] Salvaged DNS response by ignoring malformed Additional section"
                        );
                        return Ok(salvaged);
                    }
                }
            }
            Err(e)
        }
    }
}

/// RFC 6672 DNAME suffix substitution with strict length validation.
pub fn dname_substitute(name: &Name, dname_owner: &Name, target: &Name) -> Result<Name, ResponseCode> {
    if !dname_owner.zone_of(name) || dname_owner == name {
        return Err(ResponseCode::FormErr);
    }
    let name_str = name.to_string().to_lowercase();
    let owner_str = dname_owner.to_string().to_lowercase();
    if !name_str.ends_with(&owner_str) {
        return Err(ResponseCode::FormErr);
    }
    let prefix = &name_str[..name_str.len() - owner_str.len()];
    let target_str = target.to_string();
    let new_name_str = format!("{}{}", prefix, target_str);

    // RFC 6672 §2.2: Name length limit (255) and label length limit (63)
    if new_name_str.len() > 255 {
        return Err(ResponseCode::YXDomain);
    }
    for label in new_name_str.trim_end_matches('.').split('.') {
        if label.len() > 63 {
            return Err(ResponseCode::YXDomain);
        }
    }

    Name::from_str(&new_name_str).map_err(|_| ResponseCode::YXDomain)
}

pub fn extract_dname_target(record: &Record) -> Option<Name> {
    if record.record_type() == DNAME_RECORD_TYPE {
        let mut buf = Vec::new();
        let mut encoder = BinEncoder::new(&mut buf);
        record.data().emit(&mut encoder).ok()?;
        let mut decoder = BinDecoder::new(&buf);
        return Name::read(&mut decoder).ok();
    }
    None
}

fn is_safe_upstream_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
            {
                return false;
            }
            let o = v4.octets();
            if o[0] == 100 && (o[1] & 0b1100_0000) == 0b0100_0000 {
                return false;
            }
            if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
                return false;
            }
            if o[0] == 0 {
                return false;
            }
            true
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return false;
            }
            let seg0 = v6.segments()[0];
            if (seg0 & 0xfe00) == 0xfc00 {
                return false;
            }
            if (seg0 & 0xffc0) == 0xfe80 {
                return false;
            }
            let seg = v6.segments();
            if seg[0] == 0 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0xffff {
                let mapped = Ipv4Addr::new(
                    (seg[6] >> 8) as u8,
                    (seg[6] & 0xff) as u8,
                    (seg[7] >> 8) as u8,
                    (seg[7] & 0xff) as u8,
                );
                return is_safe_upstream_ip(IpAddr::V4(mapped));
            }
            true
        }
    }
}

fn filter_safe_ips(ips: Vec<IpAddr>) -> Vec<IpAddr> {
    ips.into_iter().filter(|ip| is_safe_upstream_ip(*ip)).collect()
}

/// Merges an alias redirection hop into the target response.
///
/// Point 15: Preserves the final result's RCODE, answers, authority, and additionals,
/// while also merging any DNSSEC-relevant material (NSEC, NSEC3, RRSIG, DNSKEY) from
/// the first redirection hop so the DNSSEC validator can authenticate the entire chain.
fn merge_redirection_response(
    orig_name: &Name,
    orig_type: RecordType,
    first_hop_msg: &Message,
    final_msg: Message,
) -> Message {
    let mut final_response = Message::new();
    final_response.set_id(final_msg.id());
    final_response.set_message_type(MessageType::Response);
    final_response.set_op_code(final_msg.op_code());
    final_response.set_authoritative(final_msg.authoritative());
    final_response.set_truncated(final_msg.truncated());
    final_response.set_recursion_desired(final_msg.recursion_desired());
    final_response.set_recursion_available(final_msg.recursion_available());
    final_response.set_authentic_data(final_msg.authentic_data());
    final_response.set_checking_disabled(final_msg.checking_disabled());
    final_response.set_response_code(final_msg.response_code());

    let mut q = Query::new();
    q.set_name(orig_name.clone());
    q.set_query_type(orig_type);
    q.set_query_class(DNSClass::IN);
    final_response.add_query(q);

    // 1. Answers: first-hop records (CNAME/DNAME + RRSIGs) followed by final target answers
    for r in first_hop_msg.answers() {
        final_response.add_answer(r.clone());
    }

    for r in final_msg.answers() {
        if !final_response.answers().iter().any(|existing| existing == r) {
            final_response.add_answer(r.clone());
        }
    }

    // 2. Authority: final target authority records (SOA, NSEC/NSEC3), plus any
    // DNSSEC proof records from the first hop (e.g. wildcard denial proofs)
    for r in final_msg.name_servers() {
        final_response.add_name_server(r.clone());
    }

    for r in first_hop_msg.name_servers() {
        let is_dnssec = matches!(
            r.record_type(),
            RecordType::NSEC | RecordType::NSEC3 | RecordType::RRSIG
        );
        if is_dnssec && !final_response.name_servers().iter().any(|existing| existing == r) {
            final_response.add_name_server(r.clone());
        }
    }

    // 3. Additionals: final additionals, plus any first-hop DNSSEC records (excluding OPT)
    for r in final_msg.additionals() {
        if r.record_type() != RecordType::OPT {
            final_response.add_additional(r.clone());
        }
    }

    for r in first_hop_msg.additionals() {
        let is_dnssec = matches!(r.record_type(), RecordType::RRSIG | RecordType::DNSKEY);
        if is_dnssec && !final_response.additionals().iter().any(|existing| existing == r) {
            final_response.add_additional(r.clone());
        }
    }

    // Preserve EDNS from final message
    if let Some(edns) = final_msg.extensions().as_ref() {
        final_response.set_edns(edns.clone());
    }

    final_response
}

impl RecursiveResolver {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            delegation_cache: DashMap::new(),
        })
    }

    pub async fn resolve(&self, name: &Name, rtype: RecordType) -> Result<Message, RecursorError> {
        let mut visited: HashSet<String> = HashSet::new();
        self.resolve_internal(name, rtype, 0, &mut visited).await
    }

    fn resolve_internal<'a>(
        &'a self,
        name: &'a Name,
        rtype: RecordType,
        depth: usize,
        visited: &'a mut HashSet<String>,
    ) -> Pin<Box<dyn Future<Output = Result<Message, RecursorError>> + Send + 'a>> {
        Box::pin(async move {
            if depth > MAX_DEPTH {
                return Err(RecursorError::DepthExceeded);
            }

            let start_ips = self
                .find_cached_start(name, rtype)
                .unwrap_or_else(|| ROOT_SERVERS.iter().filter_map(|ip| ip.parse().ok()).collect());
            let mut current_servers: Vec<SocketAddr> =
                start_ips.into_iter().map(|ip| SocketAddr::new(ip, 53)).collect();

            let mut last_zone: Option<Name> = None;
            let mut bailiwick: Name = Name::root();

            for _step in 0..MAX_STEPS {
                let response = match Self::query_servers_with_fallback(&current_servers, name, rtype).await {
                    Some(r) => r,
                    None => return Err(RecursorError::AllNameserversFailed),
                };

                // 1. Exact positive answer, CNAME, or DNAME redirection
                if !response.answers().is_empty() {
                    let has_target_type = response
                        .answers()
                        .iter()
                        .any(|r| r.name() == name && r.record_type() == rtype);

                    if has_target_type {
                        return Ok(response);
                    }

                    // A. Check for CNAME
                    let cname_target = response.answers().iter().find_map(|r| {
                        if r.name() == name && r.record_type() == RecordType::CNAME {
                            if let RData::CNAME(cname) = r.data() {
                                Some(cname.0.clone())
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    });

                    if let Some(first_target) = cname_target {
                        let mut current_target = first_target;
                        let mut cname_seen = HashSet::new();
                        cname_seen.insert(name.to_string().to_lowercase());

                        // Follow intra-response CNAME chain as far as possible
                        loop {
                            let key = current_target.to_string().to_lowercase();
                            if !cname_seen.insert(key) {
                                tracing::warn!(target = %current_target, "[RECURSOR] CNAME loop in answer section; aborting");
                                return Err(RecursorError::NoProgress);
                            }

                            let target_in_answers = response
                                .answers()
                                .iter()
                                .any(|r| r.name() == &current_target && r.record_type() == rtype);

                            if target_in_answers {
                                return Ok(response);
                            }

                            let next_cname = response.answers().iter().find_map(|r| {
                                if r.name() == &current_target && r.record_type() == RecordType::CNAME {
                                    if let RData::CNAME(cname) = r.data() {
                                        Some(cname.0.clone())
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            });

                            match next_cname {
                                Some(next) => current_target = next,
                                None => break,
                            }
                        }

                        let key = format!("cname:{}", current_target.to_string().to_lowercase());
                        if visited.contains(&key) {
                            tracing::warn!(target = %current_target, "[RECURSOR] CNAME loop detected; aborting");
                            return Err(RecursorError::NoProgress);
                        }
                        visited.insert(key);

                        let cname_resp = self
                            .resolve_internal(&current_target, rtype, depth + 1, visited)
                            .await?;

                        return Ok(merge_redirection_response(name, rtype, &response, cname_resp));
                    }

                    // B. Check for DNAME
                    let dname_match = response.answers().iter().find_map(|r| {
                        if r.record_type() == DNAME_RECORD_TYPE && r.name().zone_of(name) && r.name() != name {
                            if let Some(target) = extract_dname_target(r) {
                                return Some((r.name().clone(), target, r.ttl()));
                            }
                        }
                        None
                    });

                    if let Some((dname_owner, target, dname_ttl)) = dname_match {
                        match dname_substitute(name, &dname_owner, &target) {
                            Ok(substituted) => {
                                let has_synth_cname = response.answers().iter().any(|r| {
                                    r.name() == name && r.record_type() == RecordType::CNAME
                                });

                                let mut working_response = response.clone();
                                if !has_synth_cname {
                                    let synth = Record::from_rdata(
                                        name.clone(),
                                        dname_ttl,
                                        RData::CNAME(CNAME(substituted.clone())),
                                    );
                                    working_response.add_answer(synth);
                                }

                                let substituted_in_answers = working_response
                                    .answers()
                                    .iter()
                                    .any(|r| r.name() == &substituted && r.record_type() == rtype);

                                if substituted_in_answers {
                                    return Ok(working_response);
                                }

                                let key = format!("dname:{}", substituted.to_string().to_lowercase());
                                if visited.contains(&key) {
                                    tracing::warn!(target = %substituted, "[RECURSOR] DNAME loop detected; aborting");
                                    return Err(RecursorError::NoProgress);
                                }
                                visited.insert(key);

                                let dname_resp = self
                                    .resolve_internal(&substituted, rtype, depth + 1, visited)
                                    .await?;

                                return Ok(merge_redirection_response(name, rtype, &working_response, dname_resp));
                            }
                            Err(ResponseCode::YXDomain) => {
                                tracing::warn!(
                                    name = %name,
                                    dname = %dname_owner,
                                    target = %target,
                                    "[RECURSOR] DNAME synthesis resulted in oversized domain name; returning YXDOMAIN"
                                );
                                let mut yx_msg = response.clone();
                                yx_msg.set_response_code(ResponseCode::YXDomain);
                                return Ok(yx_msg);
                            }
                            Err(_) => return Err(RecursorError::NoProgress),
                        }
                    }

                    // Fall through: non-matching answer records must not terminate recursion
                }

                // 2. Authoritative terminal responses
                let authoritative_soa = response.name_servers().iter().find_map(|r| {
                    if matches!(r.data(), RData::SOA(_)) {
                        Some(r.name())
                    } else {
                        None
                    }
                });

                if let Some(soa_zone) = authoritative_soa {
                    let is_soa_authoritative = soa_zone.zone_of(name)
                        || soa_zone == name
                        || (rtype == RecordType::DS && (name.zone_of(soa_zone) || soa_zone.zone_of(name)));

                    if is_soa_authoritative {
                        return Ok(response);
                    }
                }

                if response.response_code() == ResponseCode::NXDomain && response.authoritative() {
                    return Ok(response);
                }

                // 3. Referral processing
                // Point 17: Do not accept empty responses lacking an authoritative SOA or NS delegation
                if response.name_servers().is_empty() {
                    tracing::warn!(
                        name = %name,
                        authoritative = response.authoritative(),
                        "[RECURSOR] Received response with no relevant answers, no authoritative SOA, and no delegation; invalid"
                    );
                    return Err(RecursorError::NoProgress);
                }

                let first_ns = response
                    .name_servers()
                    .iter()
                    .find(|r| r.record_type() == RecordType::NS);

                let Some(first_ns_rec) = first_ns else {
                    return Ok(response);
                };

                let delegation_owner = first_ns_rec.name().clone();

                let mut ns_names = Vec::new();
                for r in response.name_servers() {
                    if r.record_type() == RecordType::NS {
                        if r.name() != &delegation_owner {
                            tracing::warn!(
                                expected = %delegation_owner,
                                actual = %r.name(),
                                "[SECURITY] Inconsistent NS owners in referral; rejecting"
                            );
                            return Err(RecursorError::NoProgress);
                        }
                        if let RData::NS(ns) = r.data() {
                            ns_names.push(ns.0.clone());
                        }
                    }
                }

                if ns_names.is_empty() {
                    return Ok(response);
                }

                if last_zone.as_ref() == Some(&delegation_owner) {
                    return Err(RecursorError::NoProgress);
                }

                let is_child_of_target = delegation_owner.zone_of(name) || &delegation_owner == name;
                let is_within_bailiwick = bailiwick.is_root() || bailiwick.zone_of(&delegation_owner) || bailiwick == delegation_owner;
                if !is_child_of_target || !is_within_bailiwick {
                    tracing::warn!(
                        delegation = %delegation_owner,
                        target = %name,
                        bailiwick = %bailiwick,
                        "[SECURITY] Out-of-bailiwick delegation rejected"
                    );
                    return Err(RecursorError::NoProgress);
                }

                let active_delegation = delegation_owner;

                // Extract glue from additionals
                let mut next_ips: Vec<IpAddr> = Vec::new();
                for add in response.additionals() {
                    if !ns_names.iter().any(|n| n == add.name()) {
                        continue;
                    }

                    let is_in_bailiwick = bailiwick.is_root()
                        || bailiwick.zone_of(add.name())
                        || &bailiwick == add.name()
                        || active_delegation.zone_of(add.name())
                        || &active_delegation == add.name();

                    if !is_in_bailiwick {
                        tracing::debug!(
                            ns = %add.name(),
                            delegation = %active_delegation,
                            "[SECURITY] Ignored out-of-bailiwick NS address in additionals (untrusted hint)"
                        );
                        continue;
                    }

                    match add.data() {
                        RData::A(a) => next_ips.push(IpAddr::V4(a.0)),
                        RData::AAAA(a) => next_ips.push(IpAddr::V6(a.0)),
                        _ => {}
                    }
                }

                let dropped_glue = next_ips.len();
                next_ips = filter_safe_ips(next_ips);
                if next_ips.len() != dropped_glue {
                    tracing::warn!(
                        zone = %active_delegation,
                        dropped = dropped_glue - next_ips.len(),
                        "[SECURITY] Dropped unsafe glue IP(s) in delegation"
                    );
                }

                // If glue was omitted (or out-of-bailiwick), iteratively resolve nameserver IPs
                if next_ips.is_empty() {
                    for ns_name in &ns_names {
                        let key_ns = format!("ns:resolve:{}", ns_name.to_string().to_lowercase());
                        if !visited.contains(&key_ns) {
                            visited.insert(key_ns);

                            if let Ok(ns_resp) = self
                                .resolve_internal(ns_name, RecordType::A, depth + 1, visited)
                                .await
                            {
                                for ans in ns_resp.answers() {
                                    if ans.name() == ns_name {
                                        if let RData::A(a) = ans.data() {
                                            if is_safe_upstream_ip(IpAddr::V4(a.0)) {
                                                next_ips.push(IpAddr::V4(a.0));
                                            }
                                        }
                                    }
                                }
                            }

                            if let Ok(ns_resp) = self
                                .resolve_internal(ns_name, RecordType::AAAA, depth + 1, visited)
                                .await
                            {
                                for ans in ns_resp.answers() {
                                    if ans.name() == ns_name {
                                        if let RData::AAAA(aaaa) = ans.data() {
                                            if is_safe_upstream_ip(IpAddr::V6(aaaa.0)) {
                                                next_ips.push(IpAddr::V6(aaaa.0));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if !next_ips.is_empty() {
                            break;
                        }
                    }
                }

                if next_ips.is_empty() {
                    return Err(RecursorError::GlueResolutionFailed);
                }

                let ttl = delegation_ttl(&response);
                self.delegation_cache.insert(
                    active_delegation.to_string().to_lowercase(),
                    DelegationEntry {
                        servers: next_ips.clone(),
                        expires_at: now_secs() + ttl,
                    },
                );

                bailiwick = active_delegation.clone();
                last_zone = Some(active_delegation);

                current_servers = next_ips.into_iter().map(|ip| SocketAddr::new(ip, 53)).collect();
            }

            Err(RecursorError::StepLimitExceeded)
        })
    }

    fn find_cached_start(&self, name: &Name, rtype: RecordType) -> Option<Vec<IpAddr>> {
        let now = now_secs();
        let mut current = if rtype == RecordType::DS {
            name.base_name()
        } else {
            name.clone()
        };
        loop {
            let key = current.to_string().to_lowercase();
            if let Some(entry) = self.delegation_cache.get(&key) {
                if entry.expires_at > now {
                    return Some(entry.servers.clone());
                }
            }
            if current.is_root() {
                break;
            }
            current = current.base_name();
        }
        None
    }

    /// Queries servers in concurrent batches of 3, prioritizing IPv4 to avoid
    /// failing prematurely on networks without IPv6 routes. Walks through all candidates
    /// until a valid answer is obtained.
    async fn query_servers_with_fallback(
        servers: &[SocketAddr],
        name: &Name,
        rtype: RecordType,
    ) -> Option<Message> {
        if servers.is_empty() {
            return None;
        }

        // Shuffle within address families, prioritizing IPv4.
        let mut v4: Vec<SocketAddr> = servers.iter().filter(|s| s.is_ipv4()).cloned().collect();
        let mut v6: Vec<SocketAddr> = servers.iter().filter(|s| s.is_ipv6()).cloned().collect();
        {
            v4.shuffle(&mut rand::thread_rng());
            v6.shuffle(&mut rand::thread_rng());
        }

        let mut prioritized_servers = v4;
        prioritized_servers.extend(v6);

        // Iterate through all candidate servers in chunks of 3
        for chunk in prioritized_servers.chunks(3) {
            let mut set = JoinSet::new();
            for &addr in chunk {
                let name = name.clone();
                set.spawn(async move { Self::query_socket(addr, &name, rtype).await });
            }

            while let Some(joined) = set.join_next().await {
                if let Ok(Ok(msg)) = joined {
                    match msg.response_code() {
                        ResponseCode::NoError | ResponseCode::NXDomain => {
                            return Some(msg);
                        }
                        _ => {}
                    }
                }
            }
        }

        None
    }

    async fn query_socket(
        addr: SocketAddr,
        name: &Name,
        rtype: RecordType,
    ) -> Result<Message, RecursorError> {
        if !is_safe_upstream_ip(addr.ip()) {
            tracing::warn!(ip = %addr.ip(), "[SECURITY] Refused to query unsafe upstream IP");
            return Err(RecursorError::AllNameserversFailed);
        }

        let txid: u16 = rand::thread_rng().gen();

        // 1. Primary EDNS0 Query
        let mut query_msg = Message::new();
        query_msg.set_id(txid);
        query_msg.set_message_type(MessageType::Query);
        query_msg.set_op_code(OpCode::Query);
        query_msg.set_recursion_desired(false);

        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        edns.set_dnssec_ok(true);
        query_msg.set_edns(edns);

        let mut query = Query::new();
        query.set_name(name.clone());
        query.set_query_type(rtype);
        query.set_query_class(DNSClass::IN);
        query_msg.add_query(query.clone());

        let req_bytes = query_msg.to_bytes()?;

        let bind_addr = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(ip = %addr.ip(), error = %e, "[RECURSOR] Failed to bind local socket for upstream query");
                return Err(RecursorError::AllNameserversFailed);
            }
        };

        if let Err(e) = socket.connect(addr).await {
            tracing::debug!(ip = %addr.ip(), error = %e, "[RECURSOR] Failed to connect to upstream IP (e.g. network unreachable)");
            return Err(RecursorError::AllNameserversFailed);
        }

        socket.send(&req_bytes).await?;

        let mut buf = vec![0u8; 4096];
        let n = timeout(QUERY_TIMEOUT, socket.recv(&mut buf))
            .await
            .map_err(|_| RecursorError::AllNameserversFailed)??;

        // 2. Decode UDP response with malformed Additional recovery & RFC 6891 §7 EDNS fallback
        let mut used_edns = true;
        let response = match decode_response(&buf[..n]) {
            Ok(resp) if resp.response_code() != ResponseCode::FormErr => resp,
            _ => {
                let mut plain_msg = Message::new();
                plain_msg.set_id(txid);
                plain_msg.set_message_type(MessageType::Query);
                plain_msg.set_op_code(OpCode::Query);
                plain_msg.set_recursion_desired(false);
                plain_msg.add_query(query.clone());

                let plain_bytes = plain_msg.to_bytes()?;
                socket.send(&plain_bytes).await?;

                let n = timeout(QUERY_TIMEOUT, socket.recv(&mut buf))
                    .await
                    .map_err(|_| RecursorError::AllNameserversFailed)??;

                used_edns = false;
                decode_response(&buf[..n])?
            }
        };

        if !response_matches(&response, txid, name, rtype) {
            return Err(RecursorError::AllNameserversFailed);
        }

        if response.truncated() {
            let tcp_response = timeout(TCP_TIMEOUT, async {
                let mut stream = TcpStream::connect(addr).await?;

                let tcp_query_bytes = if used_edns {
                    req_bytes
                } else {
                    let mut plain_msg = Message::new();
                    plain_msg.set_id(txid);
                    plain_msg.set_message_type(MessageType::Query);
                    plain_msg.set_op_code(OpCode::Query);
                    plain_msg.set_recursion_desired(false);
                    plain_msg.add_query(query.clone());
                    plain_msg.to_bytes()?
                };

                let len = (tcp_query_bytes.len() as u16).to_be_bytes();
                stream.write_all(&len).await?;
                stream.write_all(&tcp_query_bytes).await?;

                let mut len_buf = [0u8; 2];
                stream.read_exact(&mut len_buf).await?;
                let resp_len = u16::from_be_bytes(len_buf) as usize;
                if !(12..=65535).contains(&resp_len) {
                    return Err(RecursorError::Proto(hickory_proto::ProtoError::from("Invalid TCP frame length")));
                }

                let mut tcp_buf = vec![0u8; resp_len];
                stream.read_exact(&mut tcp_buf).await?;

                let tcp_msg = match decode_response(&tcp_buf) {
                    Ok(m) => m,
                    Err(_) => {
                        let mut plain_msg = Message::new();
                        plain_msg.set_id(txid);
                        plain_msg.set_message_type(MessageType::Query);
                        plain_msg.set_op_code(OpCode::Query);
                        plain_msg.set_recursion_desired(false);
                        plain_msg.add_query(query.clone());
                        let plain_bytes = plain_msg.to_bytes()?;

                        let len = (plain_bytes.len() as u16).to_be_bytes();
                        stream.write_all(&len).await?;
                        stream.write_all(&plain_bytes).await?;

                        let mut len_buf = [0u8; 2];
                        stream.read_exact(&mut len_buf).await?;
                        let resp_len = u16::from_be_bytes(len_buf) as usize;
                        if !(12..=65535).contains(&resp_len) {
                            return Err(RecursorError::Proto(hickory_proto::ProtoError::from("Invalid TCP frame length")));
                        }
                        let mut tcp_buf = vec![0u8; resp_len];
                        stream.read_exact(&mut tcp_buf).await?;
                        decode_response(&tcp_buf)?
                    }
                };
                Ok(tcp_msg)
            })
            .await
            .map_err(|_| RecursorError::AllNameserversFailed)?
            .map_err(|_: RecursorError| RecursorError::AllNameserversFailed)?;

            if !response_matches(&tcp_response, txid, name, rtype) {
                return Err(RecursorError::AllNameserversFailed);
            }
            return Ok(tcp_response);
        }

        Ok(response)
    }
}

fn response_matches(
    response: &Message,
    txid: u16,
    sent_name: &Name,
    rtype: RecordType,
) -> bool {
    if response.id() != txid || response.message_type() != MessageType::Response {
        return false;
    }
    if response.op_code() != OpCode::Query {
        return false;
    }
    if response.queries().len() != 1 {
        return false;
    }
    let q = &response.queries()[0];
    if q.query_type() != rtype || q.query_class() != DNSClass::IN {
        return false;
    }

    q.name() == sent_name
}

pub fn calculate_min_ttl(msg: &Message) -> u32 {
    let mut min_ttl = u32::MAX;
    for r in msg.answers() {
        min_ttl = min_ttl.min(r.ttl());
    }
    for r in msg.name_servers() {
        min_ttl = min_ttl.min(r.ttl());
    }
    for r in msg.additionals() {
        min_ttl = min_ttl.min(r.ttl());
    }
    if min_ttl == u32::MAX {
        300
    } else {
        min_ttl.min(86400)
    }
}

fn delegation_ttl(msg: &Message) -> u64 {
    let mut min_ttl = u32::MAX;
    for r in msg.name_servers() {
        min_ttl = min_ttl.min(r.ttl());
    }
    for r in msg.additionals() {
        min_ttl = min_ttl.min(r.ttl());
    }
    if min_ttl == u32::MAX {
        MIN_DELEGATION_TTL
    } else {
        (min_ttl as u64).min(MAX_DELEGATION_TTL)
    }
}