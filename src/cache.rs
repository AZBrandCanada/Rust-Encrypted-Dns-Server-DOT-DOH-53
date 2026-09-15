use crate::dnssec::DnssecStatus;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_MAX_STALE_SECS: u64 = 300;

/// RFC 8767 §4: Recommended small positive TTL (in seconds) when serving stale responses.
pub const STALE_SERVE_TTL: u32 = 30;

/// Retrieves the configured maximum allowable stale duration.
/// Can be overridden via the `MAX_STALE_SECS` environment variable.
pub fn max_stale_secs() -> u64 {
    static MAX_STALE: OnceLock<u64> = OnceLock::new();
    *MAX_STALE.get_or_init(|| {
        std::env::var("MAX_STALE_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_STALE_SECS)
    })
}

/// Explicit lifecycle state of a cached DNS response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheFreshness {
    /// Within authoritative TTL; immediately servable without background revalidation.
    Fresh,
    /// Authoritative TTL has elapsed, but within the allowable stale-while-revalidate window.
    /// Served to clients with a 30-second stale TTL and AD=0 while triggering background resolution.
    Stale,
    /// Has exceeded the maximum stale window; must be discarded and never served.
    Expired,
}

mod base64_bytes {
    use base64::prelude::*;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = BASE64_STANDARD.encode(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BASE64_STANDARD
            .decode(s.trim())
            .map_err(serde::de::Error::custom)
    }
}

fn default_dnssec_status() -> DnssecStatus {
    DnssecStatus::InsecureUnsigned
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    #[serde(with = "base64_bytes")]
    pub raw_wire: Vec<u8>,
    pub min_ttl: u32,
    pub cached_at: u64,
    pub last_revalidated_at: u64,
    #[serde(default = "default_dnssec_status")]
    pub dnssec_status: DnssecStatus,
}

impl CacheEntry {
    /// Determines the freshness of this entry at the given timestamp.
    pub fn freshness(&self, now: u64) -> CacheFreshness {
        self.freshness_at(now, max_stale_secs())
    }

    /// Evaluates freshness against an explicit stale window cutoff.
    pub fn freshness_at(&self, now: u64, max_stale: u64) -> CacheFreshness {
        let age = now.saturating_sub(self.cached_at);
        let ttl = self.min_ttl as u64;

        if age < ttl {
            CacheFreshness::Fresh
        } else if age < ttl.saturating_add(max_stale) {
            CacheFreshness::Stale
        } else {
            CacheFreshness::Expired
        }
    }
}

pub type DnsCache = Arc<DashMap<String, CacheEntry>>;

pub fn create_cache() -> DnsCache {
    Arc::new(DashMap::new())
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Loads cached entries from disk, pruning any records whose allowable freshness/stale
/// lifetime has elapsed while the server was offline (prevents zombie record resurrection).
pub fn load_cache_from_disk<P: AsRef<Path>>(cache: &DnsCache, path: P) {
    let path = path.as_ref();
    if !path.exists() {
        return;
    }

    match File::open(path) {
        Ok(file) => {
            let reader = BufReader::new(file);
            match serde_json::from_reader::<_, HashMap<String, CacheEntry>>(reader) {
                Ok(entries) => {
                    let now = now_secs();
                    let max_stale = max_stale_secs();
                    let mut inserted = 0;
                    let mut discarded = 0;

                    for (k, v) in entries {
                        if v.freshness_at(now, max_stale) == CacheFreshness::Expired {
                            discarded += 1;
                            continue;
                        }
                        cache.insert(k, v);
                        inserted += 1;
                    }
                    tracing::info!(
                        inserted = inserted,
                        discarded = discarded,
                        "[CACHE] Loaded entries from disk (pruned expired)"
                    );
                }
                Err(err) => {
                    tracing::warn!(error = %err, "[CACHE] Failed to deserialize cache; starting empty");
                }
            }
        }
        Err(err) => {
            tracing::warn!(error = %err, "[CACHE] Could not open cache file");
        }
    }
}

pub async fn save_cache_to_disk_async(cache: DnsCache, path: String) {
    tokio::task::spawn_blocking(move || {
        save_cache_to_disk_sync(&cache, &path);
    })
    .await
    .unwrap_or_default();
}

/// Atomically persists the in-memory cache to disk, filtering out expired entries
/// so dead records are not written to JSON storage.
pub fn save_cache_to_disk_sync<P: AsRef<Path>>(cache: &DnsCache, path: P) {
    let path = path.as_ref();
    let tmp_path = path.with_extension("tmp");
    match File::create(&tmp_path) {
        Ok(file) => {
            let writer = BufWriter::new(file);
            let now = now_secs();
            let max_stale = max_stale_secs();
            let mut map = HashMap::new();

            for item in cache.iter() {
                if item.value().freshness_at(now, max_stale) != CacheFreshness::Expired {
                    map.insert(item.key().clone(), item.value().clone());
                }
            }

            if let Err(err) = serde_json::to_writer(writer, &map) {
                tracing::warn!(error = %err, "[CACHE] Failed to write JSON cache to disk");
                return;
            }
            if let Err(err) = std::fs::rename(&tmp_path, path) {
                tracing::warn!(error = %err, "[CACHE] Failed to swap in new cache file");
            }
        }
        Err(err) => {
            tracing::warn!(error = %err, "[CACHE] Failed to create temp cache file on disk");
        }
    }
}