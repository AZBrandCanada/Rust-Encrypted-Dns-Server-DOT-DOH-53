// src/ratelimit.rs
use dashmap::DashMap;
use hickory_proto::rr::{Name, RecordType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, PartialEq, Eq)]
pub enum RrlAction {
    Allow,
    Truncate,
    Drop,
}

struct Bucket {
    tokens: AtomicI64,
    last_refill_millis: AtomicI64,
    last_seen_millis: AtomicI64,
}

struct DomainRateBucket {
    count: AtomicI64,
    last_reset_sec: AtomicI64,
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

    pub fn to_subnet(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(v4) => {
                let oct = v4.octets();
                IpAddr::V4(Ipv4Addr::new(oct[0], oct[1], oct[2], 0))
            }
            IpAddr::V6(v6) => {
                let seg = v6.segments();
                IpAddr::V6(Ipv6Addr::new(seg[0], seg[1], seg[2], 0, 0, 0, 0, 0))
            }
        }
    }

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

        if protocol != "UDP" {
            return RrlAction::Allow;
        }

        // RFC 8482: Drop all ANY queries over plain UDP immediately
        if qtype == RecordType::ANY {
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

        let last_refill = bucket.last_refill_millis.load(Ordering::Relaxed);
        let elapsed_ms = (now_ms - last_refill).max(0);
        if elapsed_ms > 0 {
            let new_tokens = (elapsed_ms * self.refill_per_sec) / 1000;
            if new_tokens > 0 {
                let current = bucket.tokens.load(Ordering::Relaxed);
                let updated = (current + new_tokens).min(self.capacity);
                bucket.tokens.store(updated, Ordering::Relaxed);
                bucket.last_refill_millis.store(now_ms, Ordering::Relaxed);
            }
        }

        let current_tokens = bucket.tokens.load(Ordering::Relaxed);
        if current_tokens <= 0 {
            return RrlAction::Drop;
        }
        bucket.tokens.fetch_sub(1, Ordering::Relaxed);

        let rrl_key = format!("{}:{}:{}", subnet, qname.to_string().to_lowercase(), qtype);
        let domain_entry = self.rrl_buckets.entry(rrl_key).or_insert_with(|| DomainRateBucket {
            count: AtomicI64::new(0),
            last_reset_sec: AtomicI64::new(now_s),
        });

        let last_reset = domain_entry.last_reset_sec.load(Ordering::Relaxed);
        if now_s > last_reset {
            domain_entry.count.store(1, Ordering::Relaxed);
            domain_entry.last_reset_sec.store(now_s, Ordering::Relaxed);
            return RrlAction::Allow;
        }

        let query_rate = domain_entry.count.fetch_add(1, Ordering::Relaxed) + 1;

        if query_rate == 1 {
            RrlAction::Allow
        } else if query_rate <= 3 {
            // Rapid repetition: challenge immediately with TC=1
            RrlAction::Truncate
        } else {
            // Flood detected: drop completely
            RrlAction::Drop
        }
    }

    /// Zero-Tolerance Amplification Guard:
    /// Any UDP response over 512 bytes is challenged with TC=1 (45 bytes) to guarantee ZERO amplification.
    pub fn should_challenge_large_response(
        &self,
        protocol: &str,
        client_ip: IpAddr,
        resp_bytes: usize,
    ) -> bool {
        if protocol != "UDP" || client_ip.is_loopback() {
            return false;
        }

        // Strict limit: never send > 512 bytes over plain unauthenticated UDP
        resp_bytes > 512
    }

    pub fn cleanup(&self, max_age: Duration) {
        let cutoff_ms = now_millis() - max_age.as_millis() as i64;
        let cutoff_s = cutoff_ms / 1000;

        self.subnet_buckets
            .retain(|_, b| b.last_seen_millis.load(Ordering::Relaxed) >= cutoff_ms);
        self.rrl_buckets
            .retain(|_, b| b.last_reset_sec.load(Ordering::Relaxed) >= cutoff_s);
    }

    pub fn tracked_subnets(&self) -> usize {
        self.subnet_buckets.len()
    }

    pub fn tracked_sources(&self) -> usize {
        self.tracked_subnets()
    }
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
