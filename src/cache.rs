// src/cache.rs
use base64::Engine;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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

/// A single cached answer. This is used for *both* positive answers
/// (NOERROR + records) and negative answers (NXDOMAIN, or NOERROR with
/// zero records, i.e. "NODATA" — e.g. an AAAA query against an
/// IPv4-only host). Caching NODATA is what the previous version got
/// wrong: it only cached NOERROR-with-answers or NXDOMAIN, so every
/// AAAA lookup against an IPv4-only site (extremely common — every OS
/// does this on essentially every connection) re-walked the entire
/// resolution from the root servers, every single time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    #[serde(with = "base64_bytes")]
    pub raw_wire: Vec<u8>,
    pub min_ttl: u32,
    pub cached_at: u64,
    pub last_revalidated_at: u64,
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
                    let count = entries.len();
                    for (k, v) in entries {
                        cache.insert(k, v);
                    }
                    tracing::info!(count = count, "[CACHE] Loaded existing entries from disk");
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

pub fn save_cache_to_disk<P: AsRef<Path>>(cache: &DnsCache, path: P) {
    let path = path.as_ref();
    let tmp_path = path.with_extension("tmp");
    match File::create(&tmp_path) {
        Ok(file) => {
            let writer = BufWriter::new(file);
            let mut map = HashMap::new();
            for item in cache.iter() {
                map.insert(item.key().clone(), item.value().clone());
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
