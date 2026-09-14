// src/dnssec.rs
use crate::cache::now_secs;
use crate::recursor::{calculate_min_ttl, RecursiveResolver};
use dashmap::DashMap;
use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, DS, RRSIG};
use hickory_proto::dnssec::{Algorithm, Nsec3HashAlgorithm, PublicKey};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use ml_dsa::signature::Verifier;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa44, Signature as MlDsaSignature,
    VerifyingKey as MlDsaVerifyingKey,
};
use ring::digest;
use ring::signature;
use sha2::{Digest, Sha256, Sha384};
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::OnceLock;

const MAX_SIG_CHECKS: usize = 8;               // KeyTrap (CVE-2023-50387)
const MAX_NEGATIVE_RECORDS: usize = 8;         // cap NSEC/NSEC3 records processed
const MAX_NSEC3_ITERATIONS: u16 = 150;         // RFC 9276 recommendation
const MAX_CLOSEST_ENCLOSER_STEPS: usize = 16;  // bounded walk
const MAX_CNAME_CHAIN: usize = 16;             // bounded CNAME chain walk

/// DNSSEC verdict for a response.
///
/// `Insecure` is split into two variants so the cache layer can tell the
/// difference between "this zone is genuinely unsigned" (safe to cache) and
/// "we couldn't complete validation" (must not be cached, or a transient
/// upstream failure becomes a sticky downgrade).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecStatus {
    /// Cryptographically validated end-to-end.
    Secure,
    /// Zone positively proven unsigned: the parent returned DS NODATA.
    InsecureUnsigned,
    /// Signedness could not be determined (transient chain-build failure).
    /// Served with AD=0 but MUST NOT be cached.
    InsecureUnknown,
    /// Signed zone with a failed or missing proof.
    Bogus,
}

/// Result of asking "is this name inside a signed zone?"
///
/// `Unknown` exists so that a transient DS/DNSKEY fetch failure doesn't get
/// silently conflated with "the zone is unsigned".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZoneSignedness {
    Signed,
    ProvenUnsigned,
    Unknown,
}

const ROOT_TRUST_ANCHORS: &[(u16, u8, u8, &str)] = &[
    (20326, 8, 2, "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"),
    (38696, 8, 2, "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"),
];

struct CachedZoneKeys {
    keys: Vec<DNSKEY>,
    expires_at: u64,
}

fn key_trust_cache() -> &'static DashMap<String, CachedZoneKeys> {
    static CACHE: OnceLock<DashMap<String, CachedZoneKeys>> = OnceLock::new();
    CACHE.get_or_init(DashMap::new)
}

struct SignedZoneEntry {
    signedness: ZoneSignedness,
    expires_at: u64,
}

fn signed_zone_cache() -> &'static DashMap<String, SignedZoneEntry> {
    static CACHE: OnceLock<DashMap<String, SignedZoneEntry>> = OnceLock::new();
    CACHE.get_or_init(DashMap::new)
}

enum ChainResult {
    Trusted(Vec<DNSKEY>),
    Unsigned,
    Bogus,
}

pub struct DnssecValidator;

impl DnssecValidator {
    pub async fn validate_message(
        recursor: &RecursiveResolver,
        msg: &hickory_proto::op::Message,
        qname: &Name,
        qtype: RecordType,
    ) -> DnssecStatus {
        if msg.answers().is_empty() {
            Self::validate_negative(recursor, msg, qname, qtype).await
        } else {
            let answers: Vec<Record> = msg.answers().to_vec();
            Self::validate_answer(recursor, qname, qtype, &answers).await
        }
    }

    /// Validate the answer section of a positive response.
    ///
    /// RFC 4035 §5.3.1: when following a CNAME/DNAME chain, EVERY RRset in
    /// the chain must be signed by an authorized zone, and the final RRset of
    /// the requested type must also be signed.
    pub async fn validate_answer(
        recursor: &RecursiveResolver,
        name: &Name,
        rtype: RecordType,
        all_records: &[Record],
    ) -> DnssecStatus {
        let chain: Vec<(Name, Name)> = if rtype == RecordType::CNAME {
            Vec::new()
        } else {
            collect_cname_chain(name, all_records)
        };

        for (owner, _target) in &chain {
            let cname_records: Vec<Record> = all_records
                .iter()
                .filter(|r| r.name() == owner && r.record_type() == RecordType::CNAME)
                .cloned()
                .collect();

            if cname_records.is_empty() {
                return DnssecStatus::Bogus;
            }

            match Self::validate_rrset(
                recursor,
                owner,
                RecordType::CNAME,
                &cname_records,
                all_records,
            )
            .await
            {
                DnssecStatus::Secure => {}
                other => return other,
            }
        }

        let final_owner = chain
            .last()
            .map(|(_, t)| t.clone())
            .unwrap_or_else(|| name.clone());

        let target_records: Vec<Record> = all_records
            .iter()
            .filter(|r| r.name() == &final_owner && r.record_type() == rtype)
            .cloned()
            .collect();

        if target_records.is_empty() {
            tracing::debug!(
                name = %name,
                final_owner = %final_owner,
                qtype = ?rtype,
                cname_hops = chain.len(),
                "[DNSSEC] No records of requested type at final owner; treating as Unknown"
            );
            return DnssecStatus::InsecureUnknown;
        }

        Self::validate_rrset(recursor, &final_owner, rtype, &target_records, all_records).await
    }

    /// Validate a single RRset (all records share owner + rtype).
    async fn validate_rrset(
        recursor: &RecursiveResolver,
        owner: &Name,
        rtype: RecordType,
        target_records: &[Record],
        all_records: &[Record],
    ) -> DnssecStatus {
        let rrsigs: Vec<RRSIG> = all_records
            .iter()
            .filter_map(|r| match r.data() {
                RData::DNSSEC(DNSSECRData::RRSIG(sig))
                    if sig.type_covered() == rtype && r.name() == owner =>
                {
                    Some(sig.clone())
                }
                _ => None,
            })
            .collect();

        if rrsigs.is_empty() {
            return match is_zone_signed(recursor, owner).await {
                ZoneSignedness::Signed => {
                    tracing::warn!(
                        owner = %owner,
                        qtype = ?rtype,
                        "[DNSSEC] Missing RRSIG for RRset in signed zone; Bogus"
                    );
                    DnssecStatus::Bogus
                }
                ZoneSignedness::ProvenUnsigned => {
                    tracing::debug!(
                        owner = %owner,
                        qtype = ?rtype,
                        "[DNSSEC] No RRSIG and zone proven unsigned; Insecure"
                    );
                    DnssecStatus::InsecureUnsigned
                }
                ZoneSignedness::Unknown => {
                    tracing::warn!(
                        owner = %owner,
                        qtype = ?rtype,
                        "[DNSSEC] No RRSIG and zone signedness unknown; \
                         Insecure (uncacheable)"
                    );
                    DnssecStatus::InsecureUnknown
                }
            };
        }

        let now = now_secs();

        for rrsig in &rrsigs {
            let exp = rrsig.sig_expiration().get() as u64;
            let inc = rrsig.sig_inception().get() as u64;
            if now > exp || now < inc {
                tracing::debug!(
                    owner = %owner,
                    expiration = exp,
                    inception = inc,
                    now,
                    "[DNSSEC] RRSIG outside validity window; Bogus"
                );
                return DnssecStatus::Bogus;
            }
        }

        let mut any_trusted_chain = false;

        for rrsig in &rrsigs {
            let zone = rrsig.signer_name();

            if !zone.zone_of(owner) && zone != owner {
                tracing::warn!(
                    owner = %owner,
                    signer = %zone,
                    "[DNSSEC] Unauthorized signer for RRset; returning Bogus"
                );
                return DnssecStatus::Bogus;
            }

            match Self::build_trust_chain(recursor, zone).await {
                ChainResult::Trusted(trusted_keys) => {
                    any_trusted_chain = true;
                    let mut checks_performed = 0;
                    for dnskey in &trusted_keys {
                        checks_performed += 1;
                        if checks_performed > MAX_SIG_CHECKS {
                            tracing::warn!(
                                name = %owner,
                                "[DNSSEC] Exceeded MAX_SIG_CHECKS (KeyTrap protection); aborting"
                            );
                            return DnssecStatus::Bogus;
                        }

                        let key_tag = compute_key_tag(dnskey).unwrap_or(u16::MAX);
                        let tag_match = key_tag == rrsig.key_tag();
                        let sig_ok = tag_match
                            && Self::verify_rrsig(rrsig, dnskey, owner, target_records);

                        tracing::debug!(
                            owner = %owner,
                            signer = %zone,
                            rrsig_tag = rrsig.key_tag(),
                            dnskey_tag = key_tag,
                            tag_match,
                            sig_ok,
                            "[DNSSEC] RRSIG candidate check"
                        );

                        if sig_ok {
                            return DnssecStatus::Secure;
                        }
                    }
                }
                ChainResult::Unsigned => {
                    tracing::debug!(
                        signer = %zone,
                        owner = %owner,
                        "[DNSSEC] Trust chain returned Unsigned for signer"
                    );
                }
                ChainResult::Bogus => {
                    return DnssecStatus::Bogus;
                }
            }
        }

        // RRSIGs present but none validated.
        if any_trusted_chain {
            tracing::warn!(
                owner = %owner,
                qtype = ?rtype,
                rrsig_count = rrsigs.len(),
                "[DNSSEC] No RRSIG verified against a trusted chain; Bogus"
            );
            return DnssecStatus::Bogus;
        }

        // Every signer's chain came back Unsigned, meaning a DS NODATA was
        // returned at the parent for each. That positively identifies an
        // unsigned zone, so this is InsecureUnsigned (cacheable).
        tracing::warn!(
            owner = %owner,
            qtype = ?rtype,
            rrsig_count = rrsigs.len(),
            "[DNSSEC] Validation fell through all RRSIGs with unsigned chains; Insecure"
        );
        DnssecStatus::InsecureUnsigned
    }

    async fn validate_negative(
        recursor: &RecursiveResolver,
        msg: &hickory_proto::op::Message,
        qname: &Name,
        qtype: RecordType,
    ) -> DnssecStatus {
        let soa = msg
            .name_servers()
            .iter()
            .find(|r| matches!(r.data(), RData::SOA(_)));
        let zone = match soa {
            Some(r) => r.name().clone(),
            None => {
                tracing::debug!(
                    qname = %qname,
                    "[DNSSEC] Negative response has no SOA; treating as Unknown"
                );
                return DnssecStatus::InsecureUnknown;
            }
        };

        let keys = match Self::build_trust_chain(recursor, &zone).await {
            ChainResult::Trusted(k) => k,
            ChainResult::Unsigned => {
                tracing::debug!(
                    zone = %zone,
                    qname = %qname,
                    "[DNSSEC] Negative: trust chain Unsigned; treating as Insecure"
                );
                return DnssecStatus::InsecureUnsigned;
            }
            ChainResult::Bogus => {
                tracing::warn!(
                    zone = %zone,
                    qname = %qname,
                    "[DNSSEC] Negative: trust chain Bogus"
                );
                return DnssecStatus::Bogus;
            }
        };

        let authority: Vec<Record> = msg.name_servers().to_vec();

        let has_nsec3 = authority
            .iter()
            .any(|r| r.record_type() == RecordType::NSEC3);
        if has_nsec3 {
            return Self::validate_nsec3(&keys, qname, qtype, &authority);
        }

        let has_nsec = authority
            .iter()
            .any(|r| r.record_type() == RecordType::NSEC);
        if has_nsec {
            return Self::validate_nsec(&keys, qname, qtype, &authority);
        }

        tracing::warn!(
            zone = %zone,
            qname = %qname,
            "[DNSSEC] Signed zone negative response has no NSEC/NSEC3 proof; Bogus"
        );
        DnssecStatus::Bogus
    }

    fn verify_negative_rrset(rec: &Record, authority: &[Record], keys: &[DNSKEY]) -> bool {
        let owner = rec.name().clone();
        let rtype = rec.record_type();

        let rrsigs: Vec<RRSIG> = authority
            .iter()
            .filter_map(|r| {
                if r.name() != &owner {
                    return None;
                }
                match r.data() {
                    RData::DNSSEC(DNSSECRData::RRSIG(sig))
                        if sig.type_covered() == rtype =>
                    {
                        Some(sig.clone())
                    }
                    _ => None,
                }
            })
            .collect();

        if rrsigs.is_empty() {
            return false;
        }

        let records = [rec.clone()];
        for sig in &rrsigs {
            for key in keys {
                if key.key_tag_matches(sig.key_tag())
                    && Self::verify_rrsig(sig, key, &owner, &records)
                {
                    return true;
                }
            }
        }
        false
    }

    fn validate_nsec(
        keys: &[DNSKEY],
        qname: &Name,
        qtype: RecordType,
        authority: &[Record],
    ) -> DnssecStatus {
        let nsec_records: Vec<&Record> = authority
            .iter()
            .filter(|r| r.record_type() == RecordType::NSEC)
            .take(MAX_NEGATIVE_RECORDS)
            .collect();
        if nsec_records.is_empty() {
            return DnssecStatus::Bogus;
        }

        for &nsec in &nsec_records {
            if !Self::verify_negative_rrset(nsec, authority, keys) {
                tracing::warn!(
                    owner = %nsec.name(),
                    "[DNSSEC] NSEC RRset signature did not verify; Bogus"
                );
                return DnssecStatus::Bogus;
            }
        }

        for &rec in &nsec_records {
            if rec.name() == qname {
                if let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = rec.data() {
                    let has_type = nsec.type_bit_maps().any(|t| t == qtype);
                    let has_cname = nsec.type_bit_maps().any(|t| t == RecordType::CNAME);
                    if !has_type && !has_cname {
                        return DnssecStatus::Secure;
                    }
                }
            }
        }

        let qname_covered = nsec_records.iter().any(|&rec| {
            if let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = rec.data() {
                nsec_covers(rec.name(), nsec.next_domain_name(), qname)
            } else {
                false
            }
        });
        if !qname_covered {
            return DnssecStatus::Bogus;
        }

        let closest = closest_encloser(qname, &nsec_records);
        let wildcard = wildcard_name(&closest);
        let wildcard_covered = nsec_records.iter().any(|&rec| {
            if let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = rec.data() {
                nsec_covers(rec.name(), nsec.next_domain_name(), &wildcard)
            } else {
                false
            }
        });
        if !wildcard_covered {
            return DnssecStatus::Bogus;
        }

        DnssecStatus::Secure
    }

    fn validate_nsec3(
        keys: &[DNSKEY],
        qname: &Name,
        qtype: RecordType,
        authority: &[Record],
    ) -> DnssecStatus {
        let nsec3_records: Vec<&Record> = authority
            .iter()
            .filter(|r| r.record_type() == RecordType::NSEC3)
            .take(MAX_NEGATIVE_RECORDS)
            .collect();
        if nsec3_records.is_empty() {
            return DnssecStatus::Bogus;
        }

        let first = match nsec3_records[0].data() {
            RData::DNSSEC(DNSSECRData::NSEC3(n)) => n,
            _ => return DnssecStatus::Bogus,
        };
        let salt = first.salt().to_vec();
        let iterations = first.iterations();
        let algorithm = first.hash_algorithm();

        if algorithm != Nsec3HashAlgorithm::SHA1 {
            tracing::warn!("[DNSSEC] Unsupported NSEC3 hash algorithm; Unknown");
            return DnssecStatus::InsecureUnknown;
        }
        if iterations > MAX_NSEC3_ITERATIONS {
            tracing::warn!(
                iterations,
                "[DNSSEC] NSEC3 iterations exceed RFC 9276 cap; Unknown"
            );
            return DnssecStatus::InsecureUnknown;
        }

        for &rec in &nsec3_records {
            if !Self::verify_negative_rrset(rec, authority, keys) {
                tracing::warn!(
                    owner = %rec.name(),
                    "[DNSSEC] NSEC3 RRset signature did not verify; Bogus"
                );
                return DnssecStatus::Bogus;
            }
        }

        let hashed_qname = nsec3_hash(qname, &salt, iterations);

        for &rec in &nsec3_records {
            if nsec3_owner_hash(rec).as_deref() == Some(hashed_qname.as_slice()) {
                if let RData::DNSSEC(DNSSECRData::NSEC3(n)) = rec.data() {
                    let has_type = n.type_bit_maps().any(|t| t == qtype);
                    let has_cname = n.type_bit_maps().any(|t| t == RecordType::CNAME);
                    if !has_type && !has_cname {
                        return DnssecStatus::Secure;
                    }
                }
            }
        }

        let mut closest: Option<Name> = None;
        let mut cur = qname.clone();
        let mut steps = 0usize;
        loop {
            steps += 1;
            if steps > MAX_CLOSEST_ENCLOSER_STEPS {
                return DnssecStatus::Bogus;
            }
            let h = nsec3_hash(&cur, &salt, iterations);
            if nsec3_records
                .iter()
                .any(|&r| nsec3_owner_hash(r).as_deref() == Some(h.as_slice()))
            {
                closest = Some(cur.clone());
                break;
            }
            if cur.is_root() {
                break;
            }
            cur = cur.base_name();
        }
        let closest = match closest {
            Some(c) => c,
            None => return DnssecStatus::Bogus,
        };

        if closest == *qname {
            return DnssecStatus::Bogus;
        }
        let mut next_closer = qname.clone();
        while next_closer.base_name() != closest {
            let parent = next_closer.base_name();
            if parent == next_closer {
                return DnssecStatus::Bogus;
            }
            next_closer = parent;
        }
        let hashed_next = nsec3_hash(&next_closer, &salt, iterations);

        if !nsec3_records
            .iter()
            .any(|&r| nsec3_covers(r, &hashed_next))
        {
            return DnssecStatus::Bogus;
        }

        let wildcard = wildcard_name(&closest);
        let hashed_wildcard = nsec3_hash(&wildcard, &salt, iterations);
        if !nsec3_records
            .iter()
            .any(|&r| nsec3_covers(r, &hashed_wildcard))
        {
            return DnssecStatus::Bogus;
        }

        DnssecStatus::Secure
    }

async fn build_trust_chain(recursor: &RecursiveResolver, target_zone: &Name) -> ChainResult {
        let mut path = Vec::new();
        let mut cur = target_zone.clone();
        loop {
            path.push(cur.clone());
            if cur.is_root() {
                break;
            }
            cur = cur.base_name();
        }
        path.reverse();

        let cache = key_trust_cache();
        let mut trusted_parent_keys: Option<Vec<DNSKEY>> = None;

        for zone in &path {
            let zone_key = zone.to_string().to_lowercase();

            // 1. Check cache first
            if let Some(cached) = cache.get(&zone_key) {
                if cached.expires_at > now_secs() {
                    trusted_parent_keys = Some(cached.keys.clone());
                    continue;
                }
            }

            // 2. Determine trusted DS anchors for this zone
            let trusted_ds: Vec<(u16, u8, u8, Vec<u8>)> = if zone.is_root() {
                ROOT_TRUST_ANCHORS
                    .iter()
                    .map(|(tag, alg, digest_type, hex)| {
                        (*tag, *alg, *digest_type, hex_decode(hex))
                    })
                    .collect()
            } else {
                let parent_keys = match &trusted_parent_keys {
                    Some(k) => k,
                    None => {
                        tracing::warn!(
                            zone = %zone,
                            "[DNSSEC] No trusted parent keys available; Bogus"
                        );
                        return ChainResult::Bogus;
                    }
                };

                // Query parent for DS record FIRST
                let ds_msg = match recursor.resolve(zone, RecordType::DS).await {
                    Ok(m) => m,
                    Err(err) => {
                        tracing::warn!(
                            zone = %zone,
                            error = %err,
                            "[DNSSEC] Failed to fetch DS; Bogus (fail-closed)"
                        );
                        return ChainResult::Bogus;
                    }
                };

                let ds_records: Vec<DS> = ds_msg
                    .answers()
                    .iter()
                    .filter(|r| r.name() == zone)
                    .filter_map(|r| match r.data() {
                        RData::DNSSEC(DNSSECRData::DS(d)) => Some(d.clone()),
                        _ => None,
                    })
                    .collect();

                // ---> CRUCIAL FIX: If no DS at parent, this zone is unsigned! <---
                if ds_records.is_empty() {
                    tracing::debug!(
                        zone = %zone,
                        "[DNSSEC] No DS at parent; zone is Insecure (unsigned delegation)"
                    );
                    return ChainResult::Unsigned;
                }

                let ds_rrsigs: Vec<RRSIG> = ds_msg
                    .answers()
                    .iter()
                    .filter_map(|r| match r.data() {
                        RData::DNSSEC(DNSSECRData::RRSIG(s))
                            if s.type_covered() == RecordType::DS =>
                        {
                            Some(s.clone())
                        }
                        _ => None,
                    })
                    .collect();

                if ds_rrsigs.is_empty() {
                    tracing::warn!(
                        zone = %zone,
                        "[DNSSEC] DS RRset has no RRSIG; Bogus"
                    );
                    return ChainResult::Bogus;
                }

                let ds_full_records: Vec<Record> = ds_msg
                    .answers()
                    .iter()
                    .filter(|r| r.record_type() == RecordType::DS && r.name() == zone)
                    .cloned()
                    .collect();

                let mut ds_verified = false;
                'ds: for rrsig in &ds_rrsigs {
                    for key in parent_keys {
                        if key.key_tag_matches(rrsig.key_tag())
                            && Self::verify_rrsig(rrsig, key, zone, &ds_full_records)
                        {
                            ds_verified = true;
                            break 'ds;
                        }
                    }
                }
                if !ds_verified {
                    tracing::warn!(
                        zone = %zone,
                        "[DNSSEC] Parent DS signature did not verify; Bogus"
                    );
                    return ChainResult::Bogus;
                }

                let anchors: Vec<(u16, u8, u8, Vec<u8>)> = ds_records
                    .iter()
                    .filter_map(|d| {
                        let dt = u8::from(d.digest_type());
                        let alg = u8::from(d.algorithm());
                        
                        // Check both digest type AND that the algorithm is one you actually support!
                        let alg_supported = matches!(alg, 8 | 10 | 13 | 14 | 15 | 18);

                        if (dt == 2 || dt == 4) && alg_supported {
                            Some((
                                d.key_tag(),
                                alg,
                                dt,
                                d.digest().to_vec(),
                            ))
                        } else {
                            None
                        }
                    })
                    .collect();

                if anchors.is_empty() {
                    tracing::warn!(
                        zone = %zone,
                        "[DNSSEC] DS RRset has no SHA-256 or SHA-384 digests; Unsigned"
                    );
                    return ChainResult::Unsigned;
                }

                anchors
            };

            // 3. NOW fetch DNSKEY (we know the zone is signed because a valid DS exists)
            let dnskey_msg = match recursor.resolve(zone, RecordType::DNSKEY).await {
                Ok(m) => m,
                Err(err) => {
                    tracing::warn!(
                        zone = %zone,
                        error = %err,
                        "[DNSSEC] Failed to fetch DNSKEY; Bogus (fail-closed)"
                    );
                    return ChainResult::Bogus;
                }
            };

            let candidates: Vec<DNSKEY> = dnskey_msg
                .answers()
                .iter()
                .filter(|r| r.name() == zone)
                .filter_map(|r| match r.data() {
                    RData::DNSSEC(DNSSECRData::DNSKEY(k)) => Some(k.clone()),
                    _ => None,
                })
                .collect();

            if candidates.is_empty() {
                tracing::warn!(
                    zone = %zone,
                    "[DNSSEC] DNSKEY query returned no keys for a signed zone; Bogus (fail-closed)"
                );
                return ChainResult::Bogus;
            }

            let dnskey_rrsigs: Vec<RRSIG> = dnskey_msg
                .answers()
                .iter()
                .filter_map(|r| match r.data() {
                    RData::DNSSEC(DNSSECRData::RRSIG(s))
                        if s.type_covered() == RecordType::DNSKEY =>
                    {
                        Some(s.clone())
                    }
                    _ => None,
                })
                .collect();

            if dnskey_rrsigs.is_empty() {
                tracing::warn!(
                    zone = %zone,
                    "[DNSSEC] DNSKEY RRset has no RRSIG; Bogus (fail-closed)"
                );
                return ChainResult::Bogus;
            }

            let mut matched_keys: Vec<DNSKEY> = Vec::new();
            let mut checks = 0;
            for cand in &candidates {
                checks += 1;
                if checks > MAX_SIG_CHECKS {
                    break;
                }
                let cand_tag = compute_key_tag(cand).unwrap_or(u16::MAX);
                let cand_alg = u8::from(cand.public_key().algorithm());
                for (tag, alg, digest_type, digest) in &trusted_ds {
                    if *tag == cand_tag && *alg == cand_alg {
                        if let Some(computed) = compute_ds_digest(zone, cand, *digest_type) {
                            if &computed == digest {
                                matched_keys.push(cand.clone());
                            }
                        }
                    }
                }
            }

            if matched_keys.is_empty() {
                tracing::warn!(
                    zone = %zone,
                    "[DNSSEC] Parent DS matches no published DNSKEY; returning Bogus"
                );
                return ChainResult::Bogus;
            }

            let dnskey_full_records: Vec<Record> = dnskey_msg
                .answers()
                .iter()
                .filter(|r| r.record_type() == RecordType::DNSKEY && r.name() == zone)
                .cloned()
                .collect();

            let mut dnskey_verified = false;
            'dk: for rrsig in &dnskey_rrsigs {
                for key in &matched_keys {
                    if key.key_tag_matches(rrsig.key_tag())
                        && Self::verify_rrsig(rrsig, key, zone, &dnskey_full_records)
                    {
                        dnskey_verified = true;
                        break 'dk;
                    }
                }
            }

            if !dnskey_verified {
                tracing::warn!(
                    zone = %zone,
                    "[DNSSEC] DNSKEY RRset signature did not verify; returning Bogus"
                );
                return ChainResult::Bogus;
            }

            let ttl = calculate_min_ttl(&dnskey_msg);
            cache.insert(
                zone_key,
                CachedZoneKeys {
                    keys: candidates.clone(),
                    expires_at: now_secs() + ttl as u64,
                },
            );

            trusted_parent_keys = Some(candidates);
        }

        match trusted_parent_keys {
            Some(keys) => ChainResult::Trusted(keys),
            None => ChainResult::Unsigned,
        }
    }

    fn verify_rrsig(rrsig: &RRSIG, dnskey: &DNSKEY, owner: &Name, records: &[Record]) -> bool {
        let tbs = match build_tbs(rrsig, owner, records) {
            Some(t) => t,
            None => {
                tracing::debug!(
                    owner = %owner,
                    "[DNSSEC] Failed to build TBS for RRSIG"
                );
                return false;
            }
        };

        if verify_signature(
            dnskey.public_key().algorithm(),
            dnskey.public_key().public_bytes(),
            &tbs,
            rrsig.sig(),
        ) {
            return true;
        }

        dnskey.public_key().verify(&tbs, rrsig.sig()).is_ok()
    }
}

// -------------------------------------------------------------------------
// CNAME chain helpers
// -------------------------------------------------------------------------

fn collect_cname_chain(name: &Name, records: &[Record]) -> Vec<(Name, Name)> {
    let mut chain = Vec::new();
    let mut current = name.clone();
    let mut seen: HashSet<String> = HashSet::new();

    loop {
        let key = current.to_string().to_lowercase();
        if !seen.insert(key) {
            break;
        }
        if chain.len() >= MAX_CNAME_CHAIN {
            break;
        }

        let target = records.iter().find_map(|r| {
            if r.name() == &current && r.record_type() == RecordType::CNAME {
                if let RData::CNAME(c) = r.data() {
                    return Some(c.0.clone());
                }
            }
            None
        });

        match target {
            Some(t) => {
                chain.push((current.clone(), t.clone()));
                current = t;
            }
            None => break,
        }
    }

    chain
}

// -------------------------------------------------------------------------
// Signed-zone detection for missing RRSIGs
// -------------------------------------------------------------------------

/// Ask the recursor whether `name` lies inside a signed zone.
///
/// Fast path: the SOA query response will include the SOA's RRSIG if the
/// containing zone is signed. When we see that, we return `Signed` without
/// even doing a DS lookup.
///
/// Slow path: no RRSIG on the SOA. Then query DS at the apex. A positive DS
/// means the zone is signed; a clean NODATA means it is genuinely unsigned.
/// A failure to complete either query returns `Unknown`, which propagates to
/// `DnssecStatus::InsecureUnknown` and prevents caching.
///
/// The result is cached per zone for 5 minutes, but `Unknown` results are
/// never cached so a transient failure doesn't stick.
async fn is_zone_signed(recursor: &RecursiveResolver, name: &Name) -> ZoneSignedness {
    // Cheap fast-path via the signed-zone cache.
    let cache = signed_zone_cache();
    let mut cur = name.clone();
    loop {
        let key = cur.to_string().to_lowercase();
        if let Some(entry) = cache.get(&key) {
            if entry.expires_at > now_secs() {
                match entry.signedness {
                    // ProvenUnsigned CAN be inherited down to subdomains
                    ZoneSignedness::ProvenUnsigned => return ZoneSignedness::ProvenUnsigned,

                    // Signed CANNOT be inherited from root ('.') or TLDs ('.com')!
                    ZoneSignedness::Signed => {
                        // In hickory-proto: root has 1 label (""), a TLD like "com." has 2 labels ("com", "")
                        if cur.is_root() || cur.num_labels() <= 2 {
                            if cur == *name {
                                return ZoneSignedness::Signed;
                            }
                            // Do NOT inherit Signed from '.' or a TLD downwards!
                        } else {
                            return ZoneSignedness::Signed;
                        }
                    }

                    ZoneSignedness::Unknown => {}
                }
            }
        }
        if cur.is_root() {
            break;
        }
        cur = cur.base_name();
    }

    // Fast path: SOA query returns the SOA's own RRSIG when the zone is
    // signed, so we can answer "yes" without a DS lookup.
    let soa_msg = match recursor.resolve(name, RecordType::SOA).await {
        Ok(m) => m,
        Err(_) => return ZoneSignedness::Unknown,
    };

    let soa_has_rrsig = soa_msg
        .answers()
        .iter()
        .chain(soa_msg.name_servers().iter())
        .any(|r| {
            matches!(
                r.data(),
                RData::DNSSEC(DNSSECRData::RRSIG(sig))
                    if sig.type_covered() == RecordType::SOA
            )
        });

    // Find the zone apex from the SOA (may be in answers OR authority).
    let zone = soa_msg
        .answers()
        .iter()
        .chain(soa_msg.name_servers().iter())
        .find_map(|r| {
            if matches!(r.data(), RData::SOA(_)) {
                Some(r.name().clone())
            } else {
                None
            }
        });

    let zone = match zone {
        Some(z) => z,
        None => return ZoneSignedness::Unknown,
    };

    if soa_has_rrsig {
        cache.insert(
            zone.to_string().to_lowercase(),
            SignedZoneEntry {
                signedness: ZoneSignedness::Signed,
                expires_at: now_secs() + 300,
            },
        );
        tracing::debug!(
            zone = %zone,
            queried_name = %name,
            "[DNSSEC] is_zone_signed: SOA carries RRSIG -> Signed"
        );
        return ZoneSignedness::Signed;
    }

    if zone.is_root() {
        cache.insert(
            zone.to_string().to_lowercase(),
            SignedZoneEntry {
                signedness: ZoneSignedness::Signed,
                expires_at: now_secs() + 300,
            },
        );
        return ZoneSignedness::Signed;
    }

    // Slow path: DS lookup at the apex.
    let ds_msg = match recursor.resolve(&zone, RecordType::DS).await {
        Ok(m) => m,
        Err(_) => return ZoneSignedness::Unknown,
    };

    // Presence of a DS RRset is authoritative: it means the parent has
    // committed to signing this zone. Absence means the zone is unsigned
    // (per RFC 4035 §5.2) — but only if the response actually came from the
    // parent's authoritative servers. We cannot prove that here, so we treat
    // a clean NODATA as ProvenUnsigned and cache it; anything else is
    // Unknown.
    let ds_present = ds_msg.answers().iter().any(|r| {
        r.record_type() == RecordType::DS && r.name() == &zone
    });

    let signedness = if ds_present {
        ZoneSignedness::Signed
    } else if ds_msg.response_code() == hickory_proto::op::ResponseCode::NoError {
        ZoneSignedness::ProvenUnsigned
    } else {
        ZoneSignedness::Unknown
    };

    if signedness != ZoneSignedness::Unknown {
        cache.insert(
            zone.to_string().to_lowercase(),
            SignedZoneEntry {
                signedness,
                expires_at: now_secs() + 300,
            },
        );
    }

    tracing::debug!(
        zone = %zone,
        queried_name = %name,
        ?signedness,
        "[DNSSEC] is_zone_signed resolved"
    );

    signedness
}

// -------------------------------------------------------------------------
// NSEC helpers
// -------------------------------------------------------------------------

fn wildcard_name(closest: &Name) -> Name {
    let base = closest.to_ascii();
    let base = base.trim_end_matches('.');
    Name::from_str(&format!("*.{}.", base)).unwrap_or_else(|_| Name::root())
}

fn closest_encloser(qname: &Name, nsec_records: &[&Record]) -> Name {
    let mut cur = qname.base_name();
    let mut steps = 0usize;
    loop {
        steps += 1;
        if steps > MAX_CLOSEST_ENCLOSER_STEPS {
            return Name::root();
        }
        if nsec_records.iter().any(|&r| r.name() == &cur) {
            return cur;
        }
        if cur.is_root() {
            return Name::root();
        }
        cur = cur.base_name();
    }
}

fn nsec_covers(owner: &Name, next: &Name, target: &Name) -> bool {
    if owner < next {
        owner < target && target < next
    } else {
        owner < target || target < next
    }
}

// -------------------------------------------------------------------------
// NSEC3 helpers
// -------------------------------------------------------------------------

fn nsec3_owner_hash(rec: &Record) -> Option<Vec<u8>> {
    let s = rec.name().to_string();
    let first_label = s.trim_end_matches('.').split('.').next()?;
    base32hex_decode(first_label)
}

fn nsec3_covers(rec: &Record, target_hash: &[u8]) -> bool {
    let owner_hash = match nsec3_owner_hash(rec) {
        Some(h) => h,
        None => return false,
    };
    let next_hash: Vec<u8> = match rec.data() {
        RData::DNSSEC(DNSSECRData::NSEC3(n)) => n.next_hashed_owner_name().to_vec(),
        _ => return false,
    };
    if owner_hash.as_slice() <= next_hash.as_slice() {
        owner_hash.as_slice() <= target_hash && target_hash < next_hash.as_slice()
    } else {
        owner_hash.as_slice() <= target_hash || target_hash < next_hash.as_slice()
    }
}

fn nsec3_hash(name: &Name, salt: &[u8], iterations: u16) -> Vec<u8> {
    let mut wire = Vec::new();
    for label in name.iter() {
        let bytes: &[u8] = label.as_ref();
        wire.push(bytes.len() as u8);
        wire.extend_from_slice(&bytes.to_ascii_lowercase());
    }
    wire.push(0);

    let mut data = salt.to_vec();
    data.extend_from_slice(&wire);
    let mut hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &data)
        .as_ref()
        .to_vec();

    for _ in 0..iterations {
        let mut d = hash.clone();
        d.extend_from_slice(salt);
        hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &d)
            .as_ref()
            .to_vec();
    }
    hash
}

fn base32hex_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let upper = s.to_ascii_uppercase();
    let mut bits: u64 = 0;
    let mut bit_count: u32 = 0;
    let mut out = Vec::new();
    for c in upper.bytes() {
        let val = ALPHABET.iter().position(|&x| x == c)? as u64;
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push((bits >> bit_count) as u8);
        }
    }
    Some(out)
}

// -------------------------------------------------------------------------
// Key tag, DS digest, TBS, signature verification
// -------------------------------------------------------------------------

trait KeyTagExt {
    fn key_tag_matches(&self, tag: u16) -> bool;
}

impl KeyTagExt for DNSKEY {
    fn key_tag_matches(&self, tag: u16) -> bool {
        compute_key_tag(self).unwrap_or(u16::MAX) == tag
    }
}

fn compute_key_tag(dnskey: &DNSKEY) -> Option<u16> {
    if let Ok(tag) = dnskey.calculate_key_tag() {
        return Some(tag);
    }
    let mut buf = Vec::new();
    {
        let mut encoder = BinEncoder::new(&mut buf);
        dnskey.emit(&mut encoder).ok()?;
    }
    let mut ac: u32 = 0;
    for (i, b) in buf.iter().enumerate() {
        if i % 2 == 0 {
            ac += (*b as u32) << 8;
        } else {
            ac += *b as u32;
        }
    }
    ac += (ac >> 16) & 0xFFFF;
    Some((ac & 0xFFFF) as u16)
}

fn compute_ds_digest(owner: &Name, dnskey: &DNSKEY, digest_type: u8) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    {
        let mut encoder = BinEncoder::new(&mut buf);
        encoder.set_canonical_names(true);
        let _ = owner.emit(&mut encoder);
        let _ = dnskey.emit(&mut encoder);
    }
    match digest_type {
        2 => Some(Sha256::digest(&buf).to_vec()),
        4 => Some(Sha384::digest(&buf).to_vec()),
        _ => None,
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| s.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn build_tbs(rrsig: &RRSIG, owner: &Name, records: &[Record]) -> Option<Vec<u8>> {
    let mut out = Vec::new();

    out.extend_from_slice(&(u16::from(rrsig.type_covered()).to_be_bytes()));
    out.push(u8::from(rrsig.algorithm()));
    out.push(rrsig.num_labels());
    out.extend_from_slice(&rrsig.original_ttl().to_be_bytes());
    out.extend_from_slice(&rrsig.sig_expiration().get().to_be_bytes());
    out.extend_from_slice(&rrsig.sig_inception().get().to_be_bytes());
    out.extend_from_slice(&rrsig.key_tag().to_be_bytes());

    {
        let mut name_buf = Vec::new();
        let mut encoder = BinEncoder::new(&mut name_buf);
        encoder.set_canonical_names(true);
        rrsig.signer_name().emit(&mut encoder).ok()?;
        out.extend_from_slice(&name_buf);
    }

    let sig_labels = rrsig.num_labels() as usize;
    let owner_labels = owner.num_labels() as usize;

    let canonical_owner = if owner_labels > sig_labels {
        let base = owner.trim_to(sig_labels);
        Name::from_str(&format!("*.{}", base)).unwrap_or_else(|_| owner.clone())
    } else {
        owner.clone()
    };

    struct CanonicalEntry {
        rdata_bytes: Vec<u8>,
        full_wire: Vec<u8>,
    }

    let mut entries = Vec::new();

    for rec in records {
        let mut rdata_buf = Vec::new();
        {
            let mut rdata_encoder = BinEncoder::new(&mut rdata_buf);
            rdata_encoder.set_canonical_names(true);
            rec.data().emit(&mut rdata_encoder).ok()?;
        }

        let mut full_buf = Vec::new();
        {
            let mut encoder = BinEncoder::new(&mut full_buf);
            encoder.set_canonical_names(true);
            canonical_owner.emit(&mut encoder).ok()?;
            encoder.emit_u16(u16::from(rec.record_type())).ok()?;
            encoder.emit_u16(u16::from(rec.dns_class())).ok()?;
            encoder.emit_u32(rrsig.original_ttl()).ok()?;
            encoder.emit_u16(rdata_buf.len() as u16).ok()?;
            encoder.emit_vec(&rdata_buf).ok()?;
        }

        entries.push(CanonicalEntry {
            rdata_bytes: rdata_buf,
            full_wire: full_buf,
        });
    }

    entries.sort_by(|a, b| a.rdata_bytes.cmp(&b.rdata_bytes));

    for e in entries {
        out.extend_from_slice(&e.full_wire);
    }

    Some(out)
}

fn verify_signature(algorithm: Algorithm, pubkey_bytes: &[u8], message: &[u8], sig: &[u8]) -> bool {
    match algorithm {
        Algorithm::RSASHA256 | Algorithm::RSASHA512 => {
            let Some((exponent, modulus)) = parse_rsa_public_key(pubkey_bytes) else {
                return false;
            };
            let verify_alg: &'static signature::RsaParameters =
                if algorithm == Algorithm::RSASHA256 {
                    &signature::RSA_PKCS1_2048_8192_SHA256
                } else {
                    &signature::RSA_PKCS1_2048_8192_SHA512
                };
            let components = signature::RsaPublicKeyComponents {
                n: modulus,
                e: exponent,
            };
            components.verify(verify_alg, message, sig).is_ok()
        }
        Algorithm::ECDSAP256SHA256 => {
            let mut full_key = Vec::with_capacity(65);
            full_key.push(0x04);
            full_key.extend_from_slice(pubkey_bytes);
            let key =
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &full_key);
            key.verify(message, sig).is_ok()
        }
        Algorithm::ECDSAP384SHA384 => {
            let mut full_key = Vec::with_capacity(97);
            full_key.push(0x04);
            full_key.extend_from_slice(pubkey_bytes);
            let key =
                signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, &full_key);
            key.verify(message, sig).is_ok()
        }
        Algorithm::ED25519 => {
            let key = signature::UnparsedPublicKey::new(&signature::ED25519, pubkey_bytes);
            key.verify(message, sig).is_ok()
        }
        Algorithm::Unknown(18) => verify_mldsa44(pubkey_bytes, message, sig),
        _ => false,
    }
}

fn verify_mldsa44(pubkey_bytes: &[u8], message: &[u8], sig: &[u8]) -> bool {
    let Ok(vk_enc) = EncodedVerifyingKey::<MlDsa44>::try_from(pubkey_bytes) else {
        tracing::debug!(
            len = pubkey_bytes.len(),
            "[DNSSEC] ML-DSA-44 public key has wrong length (expected 1312)"
        );
        return false;
    };
    let vk = MlDsaVerifyingKey::<MlDsa44>::decode(&vk_enc);

    let Ok(sig_enc) = EncodedSignature::<MlDsa44>::try_from(sig) else {
        tracing::debug!(
            len = sig.len(),
            "[DNSSEC] ML-DSA-44 signature has wrong length (expected 2420)"
        );
        return false;
    };
    let Some(sig_obj) = MlDsaSignature::<MlDsa44>::decode(&sig_enc) else {
        tracing::debug!("[DNSSEC] ML-DSA-44 signature decode failed");
        return false;
    };

    vk.verify(message, &sig_obj).is_ok()
}

fn parse_rsa_public_key(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    if bytes.is_empty() {
        return None;
    }
    let (exp_len, rest) = if bytes[0] == 0 {
        if bytes.len() < 3 {
            return None;
        }
        let len = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
        (len, &bytes[3..])
    } else {
        (bytes[0] as usize, &bytes[1..])
    };
    if rest.len() < exp_len {
        return None;
    }
    let (exponent, modulus) = rest.split_at(exp_len);
    if modulus.is_empty() {
        return None;
    }
    Some((exponent, modulus))
}