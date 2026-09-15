use dashmap::DashMap;
use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::op::Message;
use hickory_proto::rr::{RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_MAX_STALE_SECS: u64 = 300;

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
    /// May be served to clients (with TTL=0 and AD=0) while triggering background resolution.
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    #[serde(with = "base64_bytes")]
    pub raw_wire: Vec<u8>,
    pub min_ttl: u32,
    pub cached_at: u64,
    pub last_revalidated_at: u64,
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

    /// Prepares a client-facing wire buffer from the cached entry:
    /// 1. Decrements all Resource Record TTLs according to elapsed age (RFC 2181):
    ///    `remaining_ttl = max(original_ttl - age, 0)`.
    /// 2. Skips OPT records (RFC 6891) so EDNS flags/extended RCODE are never corrupted.
    /// 3. Preserves immutable RRSIG RDATA `Original TTL` for DNSSEC validation integrity.
    /// 4. Strips the `AD` (Authentic Data) bit if data is served stale (RFC 8767 §6)
    ///    or if any RRSIG has surpassed its cryptographic expiration.
    /// 5. Injects the client's query Transaction ID and flags.
    pub fn prepare_client_wire(
        &self,
        client_txid: u16,
        now: u64,
    ) -> Option<(Vec<u8>, CacheFreshness)> {
        self.prepare_client_wire_with_flags(client_txid, true, false, now)
    }

    /// Prepares a client-facing response wire buffer with explicit RD and CD flags.
    pub fn prepare_client_wire_with_flags(
        &self,
        client_txid: u16,
        recursion_desired: bool,
        checking_disabled: bool,
        now: u64,
    ) -> Option<(Vec<u8>, CacheFreshness)> {
        let freshness = self.freshness(now);
        if freshness == CacheFreshness::Expired {
            return None;
        }

        let mut decoder = BinDecoder::new(&self.raw_wire);
        let mut msg = Message::read(&mut decoder).ok()?;

        // Adapt headers for the requesting client
        msg.set_id(client_txid);
        msg.set_recursion_desired(recursion_desired);
        msg.set_checking_disabled(checking_disabled);
        msg.set_recursion_available(true);

        let age = now.saturating_sub(self.cached_at) as u32;

        // Decrement outer RR TTLs across all sections.
        // OPT records are explicitly excluded as their TTL field stores EDNS0 metadata.
        for record in msg.answers_mut() {
            if record.record_type() != RecordType::OPT {
                record.set_ttl(record.ttl().saturating_sub(age));
            }
        }
        for record in msg.name_servers_mut() {
            if record.record_type() != RecordType::OPT {
                record.set_ttl(record.ttl().saturating_sub(age));
            }
        }
        for record in msg.additionals_mut() {
            if record.record_type() != RecordType::OPT {
                record.set_ttl(record.ttl().saturating_sub(age));
            }
        }

        // RFC 8767 §6: Stale responses MUST NOT be served with AD=1.
        // Also ensure no expired RRSIG can ever be served as authenticated data.
        let has_expired_rrsig = msg
            .answers()
            .iter()
            .chain(msg.name_servers().iter())
            .any(|r| {
                if let RData::DNSSEC(DNSSECRData::RRSIG(sig)) = r.data() {
                    (sig.sig_expiration().get() as u64) < now
                } else {
                    false
                }
            });

        if freshness == CacheFreshness::Stale || has_expired_rrsig {
            msg.set_authentic_data(false);
        }

        let wire = msg.to_bytes().ok()?;
        Some((wire, freshness))
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