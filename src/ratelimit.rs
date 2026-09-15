use dashmap::DashMap;
use hickory_proto::rr::{Name, RecordType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_TRACKED_RRL_ENTRIES: usize = 65_536;

#[derive(Debug, PartialEq, Eq)]
pub enum RrlAction {
    /// Query is permitted to proceed normally.
    Allow,
    /// Query is challenged with a valid DNS TC=1 response (forces client to prove source IP via TCP).
    Truncate,
    /// Query is dropped silently to mitigate reflection/amplification.
    Drop,
}

struct Bucket {
    tokens: AtomicI64,
    last_refill_millis: AtomicI64,
    last_seen_millis: AtomicI64,
}

struct DomainRateBucket {
    /// Packed atomic state: upper 32 bits store `epoch_sec`, lower 32 bits store `count`.
    /// Updating both together in a single CAS transaction guarantees atomic epoch transitions.
    state: AtomicU64,
    penalized_until_sec: AtomicI64,
}

pub struct RateLimiter {
    subnet_buckets: DashMap<IpAddr, Bucket>,
    rrl_buckets: DashMap<String, DomainRateBucket>,
    capacity: i64,
    refill_per_sec: i64,
}

impl RateLimiter {
    pub fn new(capacity: i64, refill_per_sec: i64) -> Arc<Self> {
        Arc::new(Self {
            subnet_buckets: DashMap::new(),
            rrl_buckets: DashMap::new(),
            capacity,
            refill_per_sec,
        })
    }

    /// Aggregates IP addresses into /24 IPv4 subnets and /64 IPv6 prefixes.
    pub fn to_subnet(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(v4) => {
                let oct = v4.octets();
                IpAddr::V4(Ipv4Addr::new(oct[0], oct[1], oct[2], 0))
            }
            IpAddr::V6(v6) => {
                let seg = v6.segments();
                IpAddr::V6(Ipv6Addr::new(seg[0], seg[1], seg[2], seg[3], 0, 0, 0, 0))
            }
        }
    }

    /// Evaluates rate-limiting policies for an incoming query.
    ///
    /// Preserves strict separation:
    /// - All protocols use the subnet token bucket.
    /// - UDP-specific duplicate-domain RRL and ANY-drops apply exclusively to UDP.
    /// - TCP, DoT, and DoH never experience duplicate-domain penalties.
    pub fn check_query(
        &self,
        protocol: &str,
        client_ip: IpAddr,
        qname: &Name,
        qtype: RecordType,
    ) -> RrlAction {
        if client_ip.is_loopback() {
            return RrlAction::Allow;
        }

        // RFC 8482: Instantly drop UDP ANY queries to neutralize high-volume amplification
        if protocol == "UDP" && qtype == RecordType::ANY {
            return RrlAction::Drop;
        }

        let subnet = Self::to_subnet(client_ip);
        let now_ms = now_millis();
        let now_s = now_ms / 1000;

        let bucket = self.subnet_buckets.entry(subnet).or_insert_with(|| Bucket {
            tokens: AtomicI64::new(self.capacity),
            last_refill_millis: AtomicI64::new(now_ms),
            last_seen_millis: AtomicI64::new(now_ms),
        });

        bucket.last_seen_millis.store(now_ms, Ordering::Relaxed);

        // Thread-safe atomic token bucket refill
        let last_refill = bucket.last_refill_millis.load(Ordering::Acquire);
        let elapsed_ms = (now_ms - last_refill).max(0);
        if elapsed_ms > 0 {
            let new_tokens = (elapsed_ms * self.refill_per_sec) / 1000;
            if new_tokens > 0 {
                if bucket
                    .last_refill_millis
                    .compare_exchange(last_refill, now_ms, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
                {
                    let _ =
                        bucket
                            .tokens
                            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |curr| {
                                Some((curr + new_tokens).min(self.capacity))
                            });
                }
            }
        }

        // Point 24: Atomically verify and consume a token; prevents tokens from going negative under contention
        let token_acquired =
            bucket
                .tokens
                .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |curr| {
                    if curr > 0 {
                        Some(curr - 1)
                    } else {
                        None
                    }
                });

        if token_acquired.is_err() {
            return RrlAction::Drop;
        }

        // TCP, DoT, and DoH only use the subnet token bucket
        if protocol != "UDP" {
            return RrlAction::Allow;
        }

        let rrl_key = format!("{}:{}:{}", subnet, qname.to_string().to_lowercase(), qtype);

        // Mitigate table-exhaustion DoS: if table is full, do not blackhole the internet;
        // fall back to allowing new queries through to the subnet token bucket.
        if !self.rrl_buckets.contains_key(&rrl_key)
            && self.rrl_buckets.len() >= MAX_TRACKED_RRL_ENTRIES
        {
            return RrlAction::Allow;
        }

        let domain_entry = self.rrl_buckets.entry(rrl_key).or_insert_with(|| {
            let initial_state = ((now_s as u64) << 32) | 0u64;
            DomainRateBucket {
                state: AtomicU64::new(initial_state),
                penalized_until_sec: AtomicI64::new(0),
            }
        });

        let penalty = domain_entry.penalized_until_sec.load(Ordering::Acquire);
        if now_s < penalty {
            domain_entry
                .penalized_until_sec
                .store(now_s + 3, Ordering::Release);
            return RrlAction::Drop;
        }

        // Point 25: Atomic epoch transition and query counting in a single hardware transaction.
        // Upper 32 bits = epoch seconds, lower 32 bits = count.
        let mut query_count = 1;
        let _ = domain_entry
            .state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |val| {
                let curr_epoch = (val >> 32) as i64;
                let curr_count = (val & 0xFFFF_FFFF) as i64;

                if now_s > curr_epoch {
                    // New second: atomically advance epoch to now_s and reset count to 1
                    query_count = 1;
                    Some(((now_s as u64) << 32) | 1u64)
                } else {
                    // Same second: increment count
                    let new_count = (curr_count + 1).min(u32::MAX as i64);
                    query_count = new_count;
                    Some(((curr_epoch as u64) << 32) | (new_count as u64))
                }
            });

        if query_count == 1 {
            RrlAction::Allow
        } else if query_count == 2 {
            // Force client to prove authentic IP via TCP handshake (mitigates IP spoofing)
            RrlAction::Truncate
        } else {
            domain_entry
                .penalized_until_sec
                .store(now_s + 3, Ordering::Release);
            RrlAction::Drop
        }
    }

    /// Determines if an unauthenticated UDP response payload exceeds the client's advertised buffer.
    pub fn should_challenge_large_response(
        &self,
        protocol: &str,
        client_ip: IpAddr,
        resp_bytes: usize,
        client_max_payload: usize,
    ) -> bool {
        if protocol != "UDP" || client_ip.is_loopback() {
            return false;
        }
        resp_bytes > client_max_payload
    }

    /// Prunes stale buckets to bound memory usage.
    pub fn cleanup(&self, max_age: Duration) {
        let cutoff_ms = now_millis() - max_age.as_millis() as i64;
        let cutoff_s = cutoff_ms / 1000;

        self.subnet_buckets
            .retain(|_, b| b.last_seen_millis.load(Ordering::Relaxed) >= cutoff_ms);
        self.rrl_buckets.retain(|_, b| {
            let state = b.state.load(Ordering::Relaxed);
            let last_seen_s = (state >> 32) as i64;
            last_seen_s >= cutoff_s
        });
    }

    pub fn tracked_subnets(&self) -> usize {
        self.subnet_buckets.len()
    }
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
