// src/ratelimit.rs
use dashmap::DashMap;
use hickory_proto::rr::{Name, RecordType};
use std::net::IpAddr;
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
    last_seen_sec: AtomicI64,
    penalized_until_sec: AtomicI64,
}

pub struct RateLimiter {
    ip_buckets: DashMap<IpAddr, Bucket>,
    rrl_buckets: DashMap<String, DomainRateBucket>,
    capacity: i64,
    refill_per_sec: i64,
}

impl RateLimiter {
    pub fn new(capacity: i64, refill_per_sec: i64) -> Arc<Self> {
        Arc::new(Self {
            ip_buckets: DashMap::new(),
            rrl_buckets: DashMap::new(),
            capacity,
            refill_per_sec,
        })
    }

    /// Rate limits and RRL checks per individual client IP.
    /// Incorporates penalty-box dampening so floods cannot leak packets on second boundaries.
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

        // RFC 8482: Drop all ANY queries over plain UDP immediately to eliminate reflection abuse
        if qtype == RecordType::ANY {
            return RrlAction::Drop;
        }

        let now_ms = now_millis();
        let now_s = now_ms / 1000;

        // 1. Token bucket tracked strictly per client IP
        let bucket = self.ip_buckets.entry(client_ip).or_insert_with(|| Bucket {
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

        // 2. Response Rate Limiting (RRL) per Client IP + Domain + Record Type
        let rrl_key = format!("{}:{}:{}", client_ip, qname.to_string().to_lowercase(), qtype);
        let domain_entry = self.rrl_buckets.entry(rrl_key).or_insert_with(|| DomainRateBucket {
            count: AtomicI64::new(0),
            last_seen_sec: AtomicI64::new(now_s),
            penalized_until_sec: AtomicI64::new(0),
        });

        // If currently in penalty cooldown, drop and keep extending the penalty as long as traffic hits
        let penalty = domain_entry.penalized_until_sec.load(Ordering::Relaxed);
        if now_s < penalty {
            domain_entry.penalized_until_sec.store(now_s + 3, Ordering::Relaxed);
            return RrlAction::Drop;
        }

        let last_seen = domain_entry.last_seen_sec.load(Ordering::Relaxed);
        if now_s > last_seen {
            // New 1-second window. Reset query count to 1 and update timestamp
            domain_entry.count.store(1, Ordering::Relaxed);
            domain_entry.last_seen_sec.store(now_s, Ordering::Relaxed);
            return RrlAction::Allow;
        }

        let query_count = domain_entry.count.fetch_add(1, Ordering::Relaxed) + 1;

        if query_count == 1 {
            // Standard query
            RrlAction::Allow
        } else if query_count == 2 {
            // Rapid repetition: challenge with TC=1 so real clients switch to TCP (45 bytes vs 800+ bytes)
            RrlAction::Truncate
        } else {
            // Active flood detected: place in 3-second lockout penalty
            domain_entry.penalized_until_sec.store(now_s + 3, Ordering::Relaxed);
            RrlAction::Drop
        }
    }

    /// DNS Amplification Guard:
    /// Checks if a UDP response exceeds the client's supported buffer size.
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

    pub fn cleanup(&self, max_age: Duration) {
        let cutoff_ms = now_millis() - max_age.as_millis() as i64;
        let cutoff_s = cutoff_ms / 1000;

        self.ip_buckets
            .retain(|_, b| b.last_seen_millis.load(Ordering::Relaxed) >= cutoff_ms);
        self.rrl_buckets
            .retain(|_, b| b.last_seen_sec.load(Ordering::Relaxed) >= cutoff_s);
    }

    pub fn tracked_ips(&self) -> usize {
        self.ip_buckets.len()
    }

    pub fn tracked_subnets(&self) -> usize {
        self.tracked_ips()
    }

    pub fn tracked_sources(&self) -> usize {
        self.tracked_ips()
    }
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
