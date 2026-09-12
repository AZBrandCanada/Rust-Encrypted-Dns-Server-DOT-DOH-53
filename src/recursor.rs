// src/recursor.rs
//
// Core fixes vs. the previous version:
//
//   1. Delegation caching. The old resolver walked from the 13 root
//      servers on *every single query*, with no memory of "the .com TLD
//      servers are X/Y/Z" or "example.com's nameservers are A/B/C".
//      That meant every lookup paid the full root -> TLD -> authoritative
//      latency, every time, for every client. Here, every delegation we
//      learn along the way gets cached (keyed by zone, with the zone's own
//      TTL), and a new query starts from the deepest cached zone it can
//      find instead of always starting at the root.
//
//   2. Parallel nameserver racing. The old code tried nameservers one at
//      a time, waiting out a full timeout on each before trying the next.
//      A single slow/unreachable nameserver could add seconds of latency
//      per hop. Here we race several nameservers concurrently per hop and
//      take whichever answers first.
//
//   3. IPv4 *and* IPv6 glue. The old code only ever collected `A` glue
//      records from referrals, so referrals that only carried `AAAA`
//      glue (increasingly common) failed outright.
//
//   4. A real loop guard. Instead of only a numeric depth counter (which
//      still lets a misconfigured zone burn through the entire step
//      budget doing nothing), we track visited zones/names and bail out
//      immediately if a referral makes no forward progress.
//
// Negative caching (NODATA / NXDOMAIN) is *not* handled here — it's
// handled in engine.rs, which decides what's cache-worthy. This module
// only answers queries and reports what TTL a given answer carries.

use dashmap::DashMap;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable};
use rand::seq::SliceRandom;
use rand::Rng;
use std::collections::HashSet;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
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

const QUERY_TIMEOUT: Duration = Duration::from_millis(1500);
const TCP_TIMEOUT: Duration = Duration::from_millis(2000);
const MAX_PARALLEL_SERVERS: usize = 4;
const MAX_DEPTH: usize = 16;
const MAX_STEPS: usize = 16;
const MIN_DELEGATION_TTL: u64 = 300; // 5 min floor: don't re-walk pointlessly often
const MAX_DELEGATION_TTL: u64 = 172_800; // 2 day ceiling: don't trust glue forever

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
    #[error("Delegation made no forward progress (likely misconfigured zone)")]
    NoProgress,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("DNS Protocol error: {0}")]
    Proto(#[from] hickory_proto::error::ProtoError),
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
                .find_cached_start(name)
                .unwrap_or_else(|| ROOT_SERVERS.iter().filter_map(|ip| ip.parse().ok()).collect());
            let mut current_servers: Vec<SocketAddr> =
                start_ips.into_iter().map(|ip| SocketAddr::new(ip, 53)).collect();
            current_servers.shuffle(&mut rand::thread_rng());

            let mut last_zone: Option<String> = None;

            for _step in 0..MAX_STEPS {
                let response = match Self::query_servers_parallel(&current_servers, name, rtype).await {
                    Some(r) => r,
                    None => return Err(RecursorError::AllNameserversFailed),
                };

                // Case 1: direct answers or a CNAME to chase.
                if !response.answers().is_empty() {
                    let has_target_type = response
                        .answers()
                        .iter()
                        .any(|r| r.record_type() == rtype);
                    let cname_target = response.answers().iter().find_map(|r| {
                        if let Some(RData::CNAME(cname)) = r.data() {
                            Some(cname.0.clone())
                        } else {
                            None
                        }
                    });

                    if has_target_type {
                        return Ok(response);
                    } else if let Some(target) = cname_target {
                        let key = format!("cname:{}", target.to_string().to_lowercase());
                        if visited.contains(&key) {
                            // CNAME loop — just return what we have.
                            return Ok(response);
                        }
                        visited.insert(key);

                        if let Ok(cname_resp) =
                            self.resolve_internal(&target, rtype, depth + 1, visited).await
                        {
                            let mut merged = response.clone();
                            for ans in cname_resp.answers() {
                                merged.add_answer(ans.clone());
                            }
                            return Ok(merged);
                        }
                        return Ok(response);
                    } else {
                        return Ok(response);
                    }
                }

                // Case 2: authoritative NXDOMAIN.
                if response.response_code() == ResponseCode::NXDomain {
                    return Ok(response);
                }

                // Case 3: no delegation offered at all -> this is the
                // authoritative NODATA answer. Return it as-is; the
                // caller (engine.rs) decides whether/how to cache it.
                if response.name_servers().is_empty() {
                    return Ok(response);
                }

                let ns_names: Vec<Name> = response
                    .name_servers()
                    .iter()
                    .filter_map(|r| {
                        if let Some(RData::NS(ns)) = r.data() {
                            Some(ns.0.clone())
                        } else {
                            None
                        }
                    })
                    .collect();

                if ns_names.is_empty() {
                    // Authority section had records but none were NS —
                    // nothing more we can do with this response.
                    return Ok(response);
                }

                let zone_name = response
                    .name_servers()
                    .first()
                    .map(|r| r.name().to_string().to_lowercase());

                if zone_name.is_some() && zone_name == last_zone {
                    return Err(RecursorError::NoProgress);
                }

                // Collect glue: both A and AAAA.
                let mut next_ips: Vec<IpAddr> = Vec::new();
                for add in response.additionals() {
                    if !ns_names.iter().any(|n| n == add.name()) {
                        continue;
                    }
                    match add.data() {
                        Some(RData::A(a)) => next_ips.push(IpAddr::V4(a.0)),
                        Some(RData::AAAA(a)) => next_ips.push(IpAddr::V6(a.0)),
                        _ => {}
                    }
                }

                // Glueless referral: resolve one of the NS names' own A
                // record out of band.
                if next_ips.is_empty() {
                    for ns_name in &ns_names {
                        let key = format!("ns:{}", ns_name.to_string().to_lowercase());
                        if visited.contains(&key) {
                            continue;
                        }
                        visited.insert(key);

                        if let Ok(ns_resp) = self
                            .resolve_internal(ns_name, RecordType::A, depth + 1, visited)
                            .await
                        {
                            for ans in ns_resp.answers() {
                                if let Some(RData::A(a)) = ans.data() {
                                    next_ips.push(IpAddr::V4(a.0));
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

                if let Some(zone) = &zone_name {
                    let ttl = delegation_ttl(&response);
                    self.delegation_cache.insert(
                        zone.clone(),
                        DelegationEntry {
                            servers: next_ips.clone(),
                            expires_at: now_secs() + ttl,
                        },
                    );
                }

                last_zone = zone_name;
                next_ips.shuffle(&mut rand::thread_rng());
                current_servers = next_ips.into_iter().map(|ip| SocketAddr::new(ip, 53)).collect();
            }

            Err(RecursorError::StepLimitExceeded)
        })
    }

    /// Walk up from `name` through its ancestor zones looking for a
    /// cached, unexpired delegation to start from instead of the root.
    fn find_cached_start(&self, name: &Name) -> Option<Vec<IpAddr>> {
        let now = now_secs();
        let mut current = name.clone();
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

    /// Race up to MAX_PARALLEL_SERVERS nameservers concurrently and
    /// return the first usable (non-REFUSED, non-SERVFAIL) response.
    async fn query_servers_parallel(
        servers: &[SocketAddr],
        name: &Name,
        rtype: RecordType,
    ) -> Option<Message> {
        let candidates: Vec<SocketAddr> = servers.iter().take(MAX_PARALLEL_SERVERS).cloned().collect();
        if candidates.is_empty() {
            return None;
        }

        let mut set = JoinSet::new();
        for addr in candidates {
            let name = name.clone();
            set.spawn(async move { Self::query_socket(addr, &name, rtype).await });
        }

        while let Some(joined) = set.join_next().await {
            if let Ok(Ok(msg)) = joined {
                if msg.response_code() != ResponseCode::Refused
                    && msg.response_code() != ResponseCode::ServFail
                {
                    return Some(msg);
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
        let mut query_msg = Message::new();
        let txid: u16 = rand::thread_rng().gen();
        query_msg.set_id(txid);
        query_msg.set_message_type(MessageType::Query);
        query_msg.set_op_code(OpCode::Query);
        query_msg.set_recursion_desired(false); // we ARE the recursor; ask iteratively

        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        query_msg.set_edns(edns);

        let mut query = Query::new();
        query.set_name(name.clone());
        query.set_query_type(rtype);
        query.set_query_class(DNSClass::IN);
        query_msg.add_query(query);

        let req_bytes = query_msg.to_bytes()?;

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(addr).await?;
        socket.send(&req_bytes).await?;

        let mut buf = vec![0u8; 4096];
        let n = timeout(QUERY_TIMEOUT, socket.recv(&mut buf))
            .await
            .map_err(|_| RecursorError::AllNameserversFailed)??;

        let mut decoder = BinDecoder::new(&buf[..n]);
        let response = Message::read(&mut decoder)?;

        if response.truncated() {
            let mut stream = timeout(TCP_TIMEOUT, TcpStream::connect(addr))
                .await
                .map_err(|_| RecursorError::AllNameserversFailed)??;
            let len = (req_bytes.len() as u16).to_be_bytes();
            stream.write_all(&len).await?;
            stream.write_all(&req_bytes).await?;

            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await?;
            let resp_len = u16::from_be_bytes(len_buf) as usize;

            let mut tcp_buf = vec![0u8; resp_len];
            stream.read_exact(&mut tcp_buf).await?;

            let mut tcp_decoder = BinDecoder::new(&tcp_buf);
            let tcp_response = Message::read(&mut tcp_decoder)?;
            return Ok(tcp_response);
        }

        Ok(response)
    }
}

/// TTL to use for the final answer we hand back to the client.
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
    if min_ttl == u32::MAX || min_ttl == 0 {
        300
    } else {
        min_ttl.clamp(30, 86400)
    }
}

/// TTL to use for how long *we* trust a delegation (NS + glue) before
/// re-fetching it from the parent zone.
fn delegation_ttl(msg: &Message) -> u64 {
    let mut min_ttl = u32::MAX;
    for r in msg.name_servers() {
        min_ttl = min_ttl.min(r.ttl());
    }
    for r in msg.additionals() {
        min_ttl = min_ttl.min(r.ttl());
    }
    let ttl = if min_ttl == u32::MAX { MIN_DELEGATION_TTL as u32 } else { min_ttl };
    (ttl as u64).clamp(MIN_DELEGATION_TTL, MAX_DELEGATION_TTL)
}
