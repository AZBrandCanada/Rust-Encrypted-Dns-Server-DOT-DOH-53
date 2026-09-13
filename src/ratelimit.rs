// src/ratelimit.rs
//
// Two things this defends against:
//
//   1. Someone hammering the resolver directly (abuse, or a bug in a
//      client retrying too aggressively).
//   2. Using an open UDP DNS resolver as a reflection/amplification
//      vector against a third party — the classic shape is: attacker
//      spoofs a victim's IP as the query source, sends a query whose
//      answer is much bigger than the query, resolver blasts the big
//      answer at the spoofed (victim) address. Rate limiting per
//      apparent source IP caps how much amplification a single spoofed
//      identity can extract, even though it can't stop spoofing itself
//      (nothing server-side can — that requires BCP38 filtering
//      upstream, which is out of scope for this binary).
//
// This is a simple token bucket per source IP, with periodic cleanup so
// memory doesn't grow unbounded from one-off/spoofed source addresses.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct Bucket {
    tokens: AtomicI64,
    last_refill_millis: AtomicI64,
    last_seen_millis: AtomicI64,
}

pub struct RateLimiter {
    buckets: DashMap<IpAddr, Bucket>,
    capacity: i64,
    refill_per_sec: i64,
}

impl RateLimiter {
    /// `capacity`: max burst size. `refill_per_sec`: sustained queries/sec
    /// allowed per source IP after the burst is used up.
    pub fn new(capacity: i64, refill_per_sec: i64) -> Arc<Self> {
        Arc::new(Self {
            buckets: DashMap::new(),
            capacity,
            refill_per_sec,
        })
    }

    /// Returns true if this request is allowed, false if it should be
    /// dropped (no response at all — replying to a rate-limited/likely-
    /// spoofed source just adds to the amplification problem).
    pub fn allow(&self, ip: IpAddr) -> bool {
        let now = now_millis();

        let entry = self.buckets.entry(ip).or_insert_with(|| Bucket {
            tokens: AtomicI64::new(self.capacity),
            last_refill_millis: AtomicI64::new(now),
            last_seen_millis: AtomicI64::new(now),
        });

        entry.last_seen_millis.store(now, Ordering::Relaxed);

        let last_refill = entry.last_refill_millis.load(Ordering::Relaxed);
        let elapsed_ms = (now - last_refill).max(0);
        if elapsed_ms > 0 {
            let new_tokens = (elapsed_ms * self.refill_per_sec) / 1000;
            if new_tokens > 0 {
                let current = entry.tokens.load(Ordering::Relaxed);
                let updated = (current + new_tokens).min(self.capacity);
                entry.tokens.store(updated, Ordering::Relaxed);
                entry.last_refill_millis.store(now, Ordering::Relaxed);
            }
        }

        let current = entry.tokens.load(Ordering::Relaxed);
        if current > 0 {
            entry.tokens.fetch_sub(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Drop buckets for source IPs we haven't seen in a while, so a churn
    /// of one-off/spoofed addresses doesn't grow this map forever.
    pub fn cleanup(&self, max_age: Duration) {
        let cutoff = now_millis() - max_age.as_millis() as i64;
        self.buckets
            .retain(|_, bucket| bucket.last_seen_millis.load(Ordering::Relaxed) >= cutoff);
    }

    pub fn tracked_sources(&self) -> usize {
        self.buckets.len()
    }
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
