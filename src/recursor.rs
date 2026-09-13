// src/recursor.rs
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

const QUERY_TIMEOUT: Duration = Duration::from_millis(2000);
const TCP_TIMEOUT: Duration = Duration::from_millis(2500);
const MAX_DEPTH: usize = 16;
const MAX_STEPS: usize = 16;
const MIN_DELEGATION_TTL: u64 = 300;
const MAX_DELEGATION_TTL: u64 = 172_800;

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
    #[error("Delegation made no forward progress")]
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

            let mut last_zone: Option<Name> = None;
            let mut bailiwick: Name = Name::root();

            for _step in 0..MAX_STEPS {
                let response = match Self::query_servers_with_fallback(&current_servers, name, rtype).await {
                    Some(r) => r,
                    None => return Err(RecursorError::AllNameserversFailed),
                };

                // 1. Positive answer or CNAME
                if !response.answers().is_empty() {
                    let has_target_type = response
                        .answers()
                        .iter()
                        .any(|r| r.record_type() == rtype);
                    let cname_target = response.answers().iter().find_map(|r| {
                        if let RData::CNAME(cname) = r.data() {
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

                // 2. Final negative or authoritative response (NXDomain, Authoritative AA=1, or SOA present)
                if response.response_code() == ResponseCode::NXDomain
                    || response.authoritative()
                    || response.name_servers().iter().any(|r| matches!(r.data(), RData::SOA(_)))
                {
                    return Ok(response);
                }

                // 3. Referral processing
                if response.name_servers().is_empty() {
                    return Ok(response);
                }

                let ns_names: Vec<Name> = response
                    .name_servers()
                    .iter()
                    .filter_map(|r| {
                        if let RData::NS(ns) = r.data() {
                            Some(ns.0.clone())
                        } else {
                            None
                        }
                    })
                    .collect();

                if ns_names.is_empty() {
                    return Ok(response);
                }

                let zone_name = response
                    .name_servers()
                    .first()
                    .map(|r| r.name().clone());

                if let Some(ref z) = zone_name {
                    if last_zone.as_ref() == Some(z) {
                        return Err(RecursorError::NoProgress);
                    }
                }

                // Verify bailiwick boundaries
                let mut valid_delegation_zone: Option<Name> = None;
                if let Some(ref z) = zone_name {
                    let is_child_of_target = z.zone_of(name);
                    let is_within_bailiwick = bailiwick.is_root() || bailiwick.zone_of(z) || bailiwick == *z;
                    if is_child_of_target && is_within_bailiwick {
                        valid_delegation_zone = Some(z.clone());
                    } else {
                        tracing::warn!(
                            delegation = %z,
                            target = %name,
                            bailiwick = %bailiwick,
                            "[SECURITY] Out-of-bailiwick delegation rejected"
                        );
                    }
                }

                let active_delegation = match valid_delegation_zone {
                    Some(z) => z,
                    None => return Err(RecursorError::NoProgress),
                };

                // Prioritize IPv4 glue for upstream authoritative server communication
                let mut next_ips: Vec<IpAddr> = Vec::new();
                for add in response.additionals() {
                    if !ns_names.iter().any(|n| n == add.name()) {
                        continue;
                    }
                    match add.data() {
                        RData::A(a) => next_ips.push(IpAddr::V4(a.0)),
                        RData::AAAA(a) => {
                            if next_ips.is_empty() {
                                next_ips.push(IpAddr::V6(a.0));
                            }
                        }
                        _ => {}
                    }
                }

                // If glue was omitted, iteratively resolve nameserver IPs
                if next_ips.is_empty() {
                    for ns_name in &ns_names {
                        let key_a = format!("ns:a:{}", ns_name.to_string().to_lowercase());
                        if !visited.contains(&key_a) {
                            visited.insert(key_a);
                            if let Ok(ns_resp) = self
                                .resolve_internal(ns_name, RecordType::A, depth + 1, visited)
                                .await
                            {
                                for ans in ns_resp.answers() {
                                    if let RData::A(a) = ans.data() {
                                        next_ips.push(IpAddr::V4(a.0));
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

                next_ips.shuffle(&mut rand::thread_rng());
                current_servers = next_ips.into_iter().map(|ip| SocketAddr::new(ip, 53)).collect();
            }

            Err(RecursorError::StepLimitExceeded)
        })
    }

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

    async fn query_servers_with_fallback(
        servers: &[SocketAddr],
        name: &Name,
        rtype: RecordType,
    ) -> Option<Message> {
        if servers.is_empty() {
            return None;
        }

        let batch_size = 3;
        let candidates: Vec<SocketAddr> = servers.iter().take(batch_size).cloned().collect();
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

        if servers.len() > batch_size {
            let fallback: Vec<SocketAddr> = servers.iter().skip(batch_size).take(batch_size).cloned().collect();
            let mut fallback_set = JoinSet::new();
            for addr in fallback {
                let name = name.clone();
                fallback_set.spawn(async move { Self::query_socket(addr, &name, rtype).await });
            }

            while let Some(joined) = fallback_set.join_next().await {
                if let Ok(Ok(msg)) = joined {
                    if msg.response_code() != ResponseCode::Refused
                        && msg.response_code() != ResponseCode::ServFail
                    {
                        return Some(msg);
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
        let txid: u16 = rand::thread_rng().gen();

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
        query_msg.add_query(query);

        let req_bytes = query_msg.to_bytes()?;

        let bind_addr = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(addr).await?;
        socket.send(&req_bytes).await?;

        let mut buf = vec![0u8; 4096];
        let n = timeout(QUERY_TIMEOUT, socket.recv(&mut buf))
            .await
            .map_err(|_| RecursorError::AllNameserversFailed)??;

        let mut decoder = BinDecoder::new(&buf[..n]);
        let response = Message::read(&mut decoder)?;

        if !response_matches(&response, txid, name, rtype) {
            return Err(RecursorError::AllNameserversFailed);
        }

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
    let Some(q) = response.queries().first() else { return false };
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
    if min_ttl == u32::MAX || min_ttl == 0 {
        300
    } else {
        min_ttl.clamp(30, 86400)
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
    let ttl = if min_ttl == u32::MAX { MIN_DELEGATION_TTL as u32 } else { min_ttl };
    (ttl as u64).clamp(MIN_DELEGATION_TTL, MAX_DELEGATION_TTL)
}
