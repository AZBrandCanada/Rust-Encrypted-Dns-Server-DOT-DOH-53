use crate::cache::now_secs;
use crate::recursor::{
    calculate_min_ttl, dname_substitute, extract_dname_target, RecursiveResolver, DNAME_RECORD_TYPE,
};
use dashmap::DashMap;
use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, DS, RRSIG};
use hickory_proto::dnssec::{Algorithm, Nsec3HashAlgorithm, PublicKey};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use ml_dsa::signature::Verifier;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa44, Signature as MlDsaSignature,
    VerifyingKey as MlDsaVerifyingKey,
};
use ring::digest;
use ring::signature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::OnceLock;

const PER_VALIDATION_MAX_SIG_CHECKS: usize = 24;
const MAX_NEGATIVE_RECORDS: usize = 8;
const MAX_NSEC3_ITERATIONS: u16 = 150;
const MAX_CLOSEST_ENCLOSER_STEPS: usize = 16;
const MAX_CNAME_CHAIN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnssecStatus {
    Secure,
    InsecureUnsigned,
    InsecureUnknown,
    Bogus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZoneSignedness {
    Signed,
    ProvenUnsigned,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ValidationBudget {
    sig_checks: usize,
    max_sig_checks: usize,
}

impl Default for ValidationBudget {
    fn default() -> Self {
        Self {
            sig_checks: 0,
            max_sig_checks: PER_VALIDATION_MAX_SIG_CHECKS,
        }
    }
}

impl ValidationBudget {
    pub fn can_check_sig(&mut self) -> bool {
        if self.sig_checks >= self.max_sig_checks {
            false
        } else {
            self.sig_checks += 1;
            true
        }
    }
}

const ROOT_TRUST_ANCHORS: &[(u16, u8, u8, &str)] = &[
    (
        20326,
        8,
        2,
        "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
    ),
    (
        38696,
        8,
        2,
        "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
    ),
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
    Trusted { keys: Vec<DNSKEY>, ttl: u32 },
    Unsigned { ttl: u32 },
    Bogus,
}

#[derive(Debug, Clone)]
enum RedirectionStep {
    Cname {
        owner: Name,
        target: Name,
    },
    Dname {
        dname_owner: Name,
        #[allow(dead_code)]
        target: Name,
        input_name: Name,
        redirected_name: Name,
    },
}

#[derive(Debug)]
enum RedirectionChainResult {
    Complete(Vec<RedirectionStep>),
    Loop,
    TooLong,
}

pub struct DnssecValidator;

impl DnssecValidator {
    pub async fn validate_message(
        recursor: &RecursiveResolver,
        msg: &hickory_proto::op::Message,
        qname: &Name,
        qtype: RecordType,
    ) -> DnssecStatus {
        let mut budget = ValidationBudget::default();
        Self::validate_message_with_budget(recursor, msg, qname, qtype, &mut budget).await
    }

    pub async fn validate_message_with_budget(
        recursor: &RecursiveResolver,
        msg: &hickory_proto::op::Message,
        qname: &Name,
        qtype: RecordType,
        budget: &mut ValidationBudget,
    ) -> DnssecStatus {
        match msg.response_code() {
            ResponseCode::NXDomain => {
                Self::validate_negative(recursor, msg, qname, qtype, budget).await
            }
            ResponseCode::NoError if msg.answers().is_empty() => {
                Self::validate_negative(recursor, msg, qname, qtype, budget).await
            }
            ResponseCode::NoError => {
                let answers: Vec<Record> = msg.answers().to_vec();
                Self::validate_answer(recursor, qname, qtype, &answers, budget).await
            }
            _ => DnssecStatus::InsecureUnknown,
        }
    }

    pub async fn validate_answer(
        recursor: &RecursiveResolver,
        name: &Name,
        rtype: RecordType,
        all_records: &[Record],
        budget: &mut ValidationBudget,
    ) -> DnssecStatus {
        let chain = if rtype == RecordType::CNAME {
            Vec::new()
        } else {
            match collect_redirection_chain(name, all_records) {
                RedirectionChainResult::Complete(c) => c,
                RedirectionChainResult::Loop => {
                    tracing::warn!(name = %name, "[DNSSEC] Redirection cycle detected; Bogus");
                    return DnssecStatus::Bogus;
                }
                RedirectionChainResult::TooLong => {
                    tracing::warn!(name = %name, "[DNSSEC] Redirection chain exceeded limit; Bogus");
                    return DnssecStatus::Bogus;
                }
            }
        };

        for step in &chain {
            match step {
                RedirectionStep::Cname { owner, .. } => {
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
                        budget,
                    )
                    .await
                    {
                        DnssecStatus::Secure => {}
                        other => return other,
                    }
                }
                RedirectionStep::Dname {
                    dname_owner,
                    input_name,
                    ..
                } => {
                    let dname_records: Vec<Record> = all_records
                        .iter()
                        .filter(|r| r.name() == dname_owner && r.record_type() == DNAME_RECORD_TYPE)
                        .cloned()
                        .collect();

                    if dname_records.is_empty() {
                        return DnssecStatus::Bogus;
                    }

                    match Self::validate_rrset(
                        recursor,
                        dname_owner,
                        DNAME_RECORD_TYPE,
                        &dname_records,
                        all_records,
                        budget,
                    )
                    .await
                    {
                        DnssecStatus::Secure => {}
                        other => return other,
                    }

                    let synth_cname_records: Vec<Record> = all_records
                        .iter()
                        .filter(|r| r.name() == input_name && r.record_type() == RecordType::CNAME)
                        .cloned()
                        .collect();

                    let has_rrsig = all_records.iter().any(|r| match r.data() {
                        RData::DNSSEC(DNSSECRData::RRSIG(sig)) => {
                            sig.type_covered() == RecordType::CNAME && r.name() == input_name
                        }
                        _ => false,
                    });

                    if !synth_cname_records.is_empty() && has_rrsig {
                        match Self::validate_rrset(
                            recursor,
                            input_name,
                            RecordType::CNAME,
                            &synth_cname_records,
                            all_records,
                            budget,
                        )
                        .await
                        {
                            DnssecStatus::Secure => {}
                            other => return other,
                        }
                    }
                }
            }
        }

        let final_owner = match chain.last() {
            Some(RedirectionStep::Cname { target, .. }) => target.clone(),
            Some(RedirectionStep::Dname {
                redirected_name, ..
            }) => redirected_name.clone(),
            None => name.clone(),
        };

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
                redirection_hops = chain.len(),
                "[DNSSEC] No records of requested type at final owner; treating as Unknown"
            );
            return DnssecStatus::InsecureUnknown;
        }

        Self::validate_rrset(
            recursor,
            &final_owner,
            rtype,
            &target_records,
            all_records,
            budget,
        )
        .await
    }

    async fn validate_rrset(
        recursor: &RecursiveResolver,
        owner: &Name,
        rtype: RecordType,
        target_records: &[Record],
        all_records: &[Record],
        budget: &mut ValidationBudget,
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
            return match is_zone_signed(recursor, owner, budget).await {
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
                        "[DNSSEC] No RRSIG and zone signedness unknown; Insecure (uncacheable)"
                    );
                    DnssecStatus::InsecureUnknown
                }
            };
        }

        let now = now_secs();

        let mut candidates = Vec::new();
        for rrsig in &rrsigs {
            if !rrsig_time_valid(rrsig, now) {
                tracing::debug!(
                    owner = %owner,
                    sig_exp = rrsig.sig_expiration().get(),
                    sig_inc = rrsig.sig_inception().get(),
                    now,
                    "[DNSSEC] Skipping RRSIG outside validity window"
                );
                continue;
            }

            let zone = rrsig.signer_name();
            if !zone.zone_of(owner) && zone != owner {
                tracing::warn!(
                    owner = %owner,
                    signer = %zone,
                    "[DNSSEC] Skipping unauthorized signer for RRset"
                );
                continue;
            }

            candidates.push(rrsig);
        }

        if candidates.is_empty() {
            tracing::warn!(
                owner = %owner,
                qtype = ?rtype,
                rrsig_count = rrsigs.len(),
                "[DNSSEC] All RRSIGs were expired, not yet valid, or unauthorized; Bogus"
            );
            return DnssecStatus::Bogus;
        }

        let mut any_trusted_chain = false;

        for rrsig in candidates {
            let zone = rrsig.signer_name();

            match Self::build_trust_chain(recursor, zone, budget).await {
                ChainResult::Trusted {
                    keys: trusted_keys, ..
                } => {
                    any_trusted_chain = true;
                    for dnskey in &trusted_keys {
                        if !budget.can_check_sig() {
                            tracing::warn!(
                                name = %owner,
                                "[DNSSEC] Exceeded per-validation signature budget (KeyTrap protection); Bogus"
                            );
                            return DnssecStatus::Bogus;
                        }

                        let key_tag = compute_key_tag(dnskey).unwrap_or(u16::MAX);
                        let tag_match = key_tag == rrsig.key_tag();
                        let sig_ok =
                            tag_match && Self::verify_rrsig(rrsig, dnskey, owner, target_records);

                        if sig_ok {
                            return DnssecStatus::Secure;
                        }
                    }
                }
                ChainResult::Unsigned { .. } => {
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

        if any_trusted_chain {
            tracing::warn!(
                owner = %owner,
                qtype = ?rtype,
                rrsig_count = rrsigs.len(),
                "[DNSSEC] No RRSIG verified against a trusted chain; Bogus"
            );
            return DnssecStatus::Bogus;
        }

        tracing::debug!(
            owner = %owner,
            qtype = ?rtype,
            "[DNSSEC] Validation fell through all RRSIGs with unsigned chains; Insecure"
        );
        DnssecStatus::InsecureUnsigned
    }

    async fn validate_negative(
        recursor: &RecursiveResolver,
        msg: &hickory_proto::op::Message,
        qname: &Name,
        qtype: RecordType,
        budget: &mut ValidationBudget,
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

        let final_target = msg
            .answers()
            .iter()
            .rfind(|r| r.record_type() == RecordType::CNAME)
            .and_then(|r| {
                if let RData::CNAME(cname) = r.data() {
                    Some(cname.0.clone())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| qname.clone());
        if !zone.zone_of(&final_target)
            && zone != final_target
            && !zone.zone_of(qname)
            && zone != *qname
        {
            tracing::warn!(
                zone = %zone,
                qname = %qname,
                final_target = %final_target,
                "[DNSSEC] Negative response SOA is not authoritative for target; Bogus"
            );
            return DnssecStatus::Bogus;
        }

        let keys = match Self::build_trust_chain(recursor, &zone, budget).await {
            ChainResult::Trusted { keys: k, .. } => k,
            ChainResult::Unsigned { .. } => {
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

        if let Some(soa_rec) = soa {
            if !Self::verify_negative_rrset(soa_rec, &authority, &keys, budget) {
                tracing::warn!(
                    zone = %zone,
                    qname = %qname,
                    "[DNSSEC] Negative response SOA signature did not verify; Bogus"
                );
                return DnssecStatus::Bogus;
            }
        }

        let has_nsec3 = authority
            .iter()
            .any(|r| r.record_type() == RecordType::NSEC3);
        if has_nsec3 {
            return Self::validate_nsec3(&keys, &final_target, qtype, &authority, budget);
        }

        let has_nsec = authority
            .iter()
            .any(|r| r.record_type() == RecordType::NSEC);
        if has_nsec {
            return Self::validate_nsec(&keys, &final_target, qtype, &authority, budget);
        }

        tracing::warn!(
            zone = %zone,
            qname = %qname,
            "[DNSSEC] Signed zone negative response has no NSEC/NSEC3 proof; Bogus"
        );
        DnssecStatus::Bogus
    }

    fn verify_negative_rrset(
        rec: &Record,
        authority: &[Record],
        keys: &[DNSKEY],
        budget: &mut ValidationBudget,
    ) -> bool {
        let owner = rec.name().clone();
        let rtype = rec.record_type();

        let rrsigs: Vec<RRSIG> = authority
            .iter()
            .filter_map(|r| {
                if r.name() != &owner {
                    return None;
                }
                match r.data() {
                    RData::DNSSEC(DNSSECRData::RRSIG(sig)) if sig.type_covered() == rtype => {
                        Some(sig.clone())
                    }
                    _ => None,
                }
            })
            .collect();

        if rrsigs.is_empty() {
            return false;
        }

        let full_rrset: Vec<Record> = authority
            .iter()
            .filter(|r| r.name() == &owner && r.record_type() == rtype)
            .cloned()
            .collect();

        if full_rrset.is_empty() {
            return false;
        }

        for sig in &rrsigs {
            for key in keys {
                if key.key_tag_matches(sig.key_tag()) {
                    if !budget.can_check_sig() {
                        return false;
                    }
                    if Self::verify_rrsig(sig, key, &owner, &full_rrset) {
                        return true;
                    }
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
        budget: &mut ValidationBudget,
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
            if !Self::verify_negative_rrset(nsec, authority, keys, budget) {
                tracing::warn!(
                    owner = %nsec.name(),
                    "[DNSSEC] NSEC RRset signature did not verify; Bogus"
                );
                return DnssecStatus::Bogus;
            }
        }

        if let Some(status) = check_nsec_nodata(qname, qtype, &nsec_records) {
            return status;
        }

        let closest = match find_nsec_closest_encloser(qname, &nsec_records) {
            Some(c) => c,
            None => return DnssecStatus::Bogus,
        };

        if let Some(status) = check_nsec_wildcard_nodata(qname, qtype, &closest, &nsec_records) {
            return status;
        }

        if let Some(status) = check_nsec_nxdomain(qname, &closest, &nsec_records) {
            return status;
        }

        DnssecStatus::Bogus
    }

    fn validate_nsec3(
        keys: &[DNSKEY],
        qname: &Name,
        qtype: RecordType,
        authority: &[Record],
        budget: &mut ValidationBudget,
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
            match rec.data() {
                RData::DNSSEC(DNSSECRData::NSEC3(n)) => {
                    if n.hash_algorithm() != algorithm
                        || n.iterations() != iterations
                        || n.salt() != salt.as_slice()
                    {
                        tracing::warn!("[DNSSEC] Inconsistent NSEC3 parameters in proof; Bogus");
                        return DnssecStatus::Bogus;
                    }
                }
                _ => return DnssecStatus::Bogus,
            }
        }

        for &rec in &nsec3_records {
            if !Self::verify_negative_rrset(rec, authority, keys, budget) {
                tracing::warn!(
                    owner = %rec.name(),
                    "[DNSSEC] NSEC3 RRset signature did not verify; Bogus"
                );
                return DnssecStatus::Bogus;
            }
        }

        if let Some(status) = check_nsec3_nodata(qname, qtype, &nsec3_records, &salt, iterations) {
            return status;
        }

        let mut closest =
            find_nsec3_closest_provable_encloser(qname, &nsec3_records, &salt, iterations);

        if closest.is_none() && qtype == RecordType::DS {
            closest = Some(qname.base_name());
        }

        let closest = match closest {
            Some(c) => c,
            None => return DnssecStatus::Bogus,
        };

        if closest == *qname {
            return DnssecStatus::Bogus;
        }

        if let Some(status) =
            check_nsec3_wildcard_nodata(&closest, qtype, &nsec3_records, &salt, iterations)
        {
            return status;
        }

        if let Some(status) =
            check_nsec3_nxdomain(qname, &closest, qtype, &nsec3_records, &salt, iterations)
        {
            return status;
        }

        DnssecStatus::Bogus
    }

    async fn build_trust_chain(
        recursor: &RecursiveResolver,
        target_zone: &Name,
        budget: &mut ValidationBudget,
    ) -> ChainResult {
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
        let mut last_ttl = 300u32;

        for zone in &path {
            let zone_key = zone.to_string().to_lowercase();

            if let Some(cached) = cache.get(&zone_key) {
                if cached.expires_at > now_secs() {
                    trusted_parent_keys = Some(cached.keys.clone());
                    continue;
                }
            }

            let mut parent_ds_ttl = 300u32;

            let trusted_ds: Vec<(u16, u8, u8, Vec<u8>)> = if zone.is_root() {
                ROOT_TRUST_ANCHORS
                    .iter()
                    .filter_map(|(tag, alg, digest_type, hex)| {
                        hex_decode(hex).map(|bytes| (*tag, *alg, *digest_type, bytes))
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

                let ds_ttl = calculate_min_ttl(&ds_msg);
                parent_ds_ttl = ds_ttl;

                let ds_records: Vec<DS> = ds_msg
                    .answers()
                    .iter()
                    .filter(|r| r.name() == zone)
                    .filter_map(|r| match r.data() {
                        RData::DNSSEC(DNSSECRData::DS(d)) => Some(d.clone()),
                        _ => None,
                    })
                    .collect();

                if ds_records.is_empty() {
                    let authority = ds_msg.name_servers();
                    let denial_status = if authority
                        .iter()
                        .any(|r| r.record_type() == RecordType::NSEC3)
                    {
                        Self::validate_nsec3(parent_keys, zone, RecordType::DS, authority, budget)
                    } else if authority
                        .iter()
                        .any(|r| r.record_type() == RecordType::NSEC)
                    {
                        Self::validate_nsec(parent_keys, zone, RecordType::DS, authority, budget)
                    } else {
                        DnssecStatus::Bogus
                    };

                    match denial_status {
                        DnssecStatus::Secure | DnssecStatus::InsecureUnsigned => {
                            let ds_proof_ttl = calculate_min_ttl(&ds_msg);
                            tracing::debug!(
                                zone = %zone,
                                "[DNSSEC] Authenticated denial of DS verified: zone is Insecure"
                            );
                            return ChainResult::Unsigned { ttl: ds_proof_ttl };
                        }
                        _ => {
                            tracing::warn!(
                                zone = %zone,
                                denial_status = ?denial_status,
                                "[DNSSEC] DS missing but denial proof failed; Bogus (fail-closed)"
                            );
                            return ChainResult::Bogus;
                        }
                    }
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
                    tracing::warn!(zone = %zone, "[DNSSEC] DS RRset has no RRSIG; Bogus");
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
                        if key.key_tag_matches(rrsig.key_tag()) {
                            if !budget.can_check_sig() {
                                tracing::warn!(
                                    "[DNSSEC] Work budget exhausted verifying DS; Bogus"
                                );
                                return ChainResult::Bogus;
                            }
                            if Self::verify_rrsig(rrsig, key, zone, &ds_full_records) {
                                ds_verified = true;
                                break 'ds;
                            }
                        }
                    }
                }
                if !ds_verified {
                    tracing::warn!(zone = %zone, "[DNSSEC] Parent DS signature did not verify; Bogus");
                    return ChainResult::Bogus;
                }

                let anchors: Vec<(u16, u8, u8, Vec<u8>)> = ds_records
                    .iter()
                    .filter_map(|d| {
                        let dt = u8::from(d.digest_type());
                        let alg = u8::from(d.algorithm());
                        let alg_supported = matches!(alg, 8 | 10 | 13 | 14 | 15 | 18);

                        if (dt == 2 || dt == 4) && alg_supported {
                            Some((d.key_tag(), alg, dt, d.digest().to_vec()))
                        } else {
                            None
                        }
                    })
                    .collect();

                if anchors.is_empty() {
                    let ds_ttl = calculate_min_ttl(&ds_msg);
                    tracing::warn!(
                        zone = %zone,
                        "[DNSSEC] DS RRset has no supported SHA-256 or SHA-384 digests; Unsigned"
                    );
                    return ChainResult::Unsigned { ttl: ds_ttl };
                }

                anchors
            };

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
                tracing::warn!(zone = %zone, "[DNSSEC] DNSKEY query returned no keys; Bogus");
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
                tracing::warn!(zone = %zone, "[DNSSEC] DNSKEY RRset has no RRSIG; Bogus");
                return ChainResult::Bogus;
            }

            let mut matched_keys: Vec<DNSKEY> = Vec::new();
            for cand in &candidates {
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
                    if key.key_tag_matches(rrsig.key_tag()) {
                        if !budget.can_check_sig() {
                            tracing::warn!(
                                "[DNSSEC] Work budget exhausted verifying DNSKEY; Bogus"
                            );
                            return ChainResult::Bogus;
                        }
                        if Self::verify_rrsig(rrsig, key, zone, &dnskey_full_records) {
                            dnskey_verified = true;
                            break 'dk;
                        }
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

            let dnskey_ttl = calculate_min_ttl(&dnskey_msg);

            let effective_ttl = if zone.is_root() {
                dnskey_ttl
            } else {
                dnskey_ttl.min(parent_ds_ttl)
            };
            last_ttl = effective_ttl;

            let authenticated_zone_keys: Vec<DNSKEY> = candidates
                .into_iter()
                .filter(|k| (k.flags() & 0x0100) != 0)
                .collect();

            cache.insert(
                zone_key,
                CachedZoneKeys {
                    keys: authenticated_zone_keys.clone(),
                    expires_at: now_secs() + effective_ttl as u64,
                },
            );

            trusted_parent_keys = Some(authenticated_zone_keys);
        }

        match trusted_parent_keys {
            Some(keys) => ChainResult::Trusted {
                keys,
                ttl: last_ttl,
            },
            None => ChainResult::Unsigned { ttl: last_ttl },
        }
    }

    fn verify_rrsig(rrsig: &RRSIG, dnskey: &DNSKEY, owner: &Name, records: &[Record]) -> bool {
        let now = now_secs();
        if !rrsig_time_valid(rrsig, now) {
            tracing::debug!(
                owner = %owner,
                sig_exp = rrsig.sig_expiration().get(),
                sig_inc = rrsig.sig_inception().get(),
                now,
                "[DNSSEC] RRSIG validity period violated"
            );
            return false;
        }

        if rrsig.algorithm() != dnskey.public_key().algorithm() {
            tracing::debug!(
                rrsig_alg = ?rrsig.algorithm(),
                dnskey_alg = ?dnskey.public_key().algorithm(),
                "[DNSSEC] Algorithm mismatch between RRSIG and DNSKEY"
            );
            return false;
        }

        let tbs = match build_tbs(rrsig, owner, records) {
            Some(t) => t,
            None => {
                tracing::debug!(owner = %owner, "[DNSSEC] Failed to build TBS for RRSIG");
                return false;
            }
        };

        if verify_signature(
            rrsig.algorithm(),
            dnskey.public_key().public_bytes(),
            &tbs,
            rrsig.sig(),
        ) {
            return true;
        }

        dnskey.public_key().verify(&tbs, rrsig.sig()).is_ok()
    }
}

fn find_nsec_closest_encloser(qname: &Name, nsec_records: &[&Record]) -> Option<Name> {
    let mut cur = if qname.is_root() {
        qname.clone()
    } else {
        qname.base_name()
    };
    let mut steps = 0usize;
    loop {
        steps += 1;
        if steps > MAX_CLOSEST_ENCLOSER_STEPS {
            return None;
        }
        if nsec_records.iter().any(|r| r.name() == &cur) {
            return Some(cur);
        }
        if cur.is_root() {
            break;
        }
        cur = cur.base_name();
    }
    None
}

fn check_nsec_nodata(
    qname: &Name,
    qtype: RecordType,
    nsec_records: &[&Record],
) -> Option<DnssecStatus> {
    for &rec in nsec_records {
        if rec.name() == qname {
            if let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = rec.data() {
                let has_type = nsec.type_bit_maps().any(|t| t == qtype);
                let has_cname = nsec.type_bit_maps().any(|t| t == RecordType::CNAME);
                let has_soa = nsec.type_bit_maps().any(|t| t == RecordType::SOA);

                if qtype == RecordType::DS && has_soa {
                    return Some(DnssecStatus::Bogus);
                }

                if !has_type && !has_cname {
                    return Some(DnssecStatus::Secure);
                }
            }
        }
    }
    None
}

fn check_nsec_wildcard_nodata(
    qname: &Name,
    qtype: RecordType,
    closest: &Name,
    nsec_records: &[&Record],
) -> Option<DnssecStatus> {
    let wildcard = wildcard_name(closest);
    let wildcard_nsec = nsec_records.iter().find(|&&r| r.name() == &wildcard)?;
    if let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = wildcard_nsec.data() {
        let has_type = nsec.type_bit_maps().any(|t| t == qtype);
        let has_cname = nsec.type_bit_maps().any(|t| t == RecordType::CNAME);
        if has_type || has_cname {
            return None;
        }
    } else {
        return None;
    }

    let qname_covered = nsec_records.iter().any(|&rec| {
        if let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = rec.data() {
            nsec_covers(rec.name(), nsec.next_domain_name(), qname)
        } else {
            false
        }
    });

    if qname_covered {
        Some(DnssecStatus::Secure)
    } else {
        None
    }
}

fn check_nsec_nxdomain(
    qname: &Name,
    closest: &Name,
    nsec_records: &[&Record],
) -> Option<DnssecStatus> {
    let qname_covered = nsec_records.iter().any(|&rec| {
        if let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = rec.data() {
            nsec_covers(rec.name(), nsec.next_domain_name(), qname)
        } else {
            false
        }
    });
    if !qname_covered {
        return None;
    }

    let wildcard = wildcard_name(closest);
    let wildcard_covered = nsec_records.iter().any(|&rec| {
        if let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = rec.data() {
            nsec_covers(rec.name(), nsec.next_domain_name(), &wildcard)
        } else {
            false
        }
    });
    if !wildcard_covered {
        return None;
    }

    Some(DnssecStatus::Secure)
}

fn find_nsec3_closest_provable_encloser(
    qname: &Name,
    nsec3_records: &[&Record],
    salt: &[u8],
    iterations: u16,
) -> Option<Name> {
    let mut cur = qname.clone();
    let mut steps = 0usize;
    loop {
        steps += 1;
        if steps > MAX_CLOSEST_ENCLOSER_STEPS {
            return None;
        }
        let h = nsec3_hash(&cur, salt, iterations);
        if nsec3_records
            .iter()
            .any(|&r| nsec3_owner_hash(r).as_deref() == Some(h.as_slice()))
        {
            return Some(cur);
        }
        if cur.is_root() {
            break;
        }
        cur = cur.base_name();
    }
    None
}

fn check_nsec3_nodata(
    qname: &Name,
    qtype: RecordType,
    nsec3_records: &[&Record],
    salt: &[u8],
    iterations: u16,
) -> Option<DnssecStatus> {
    let hashed_qname = nsec3_hash(qname, salt, iterations);
    for &rec in nsec3_records {
        if nsec3_owner_hash(rec).as_deref() == Some(hashed_qname.as_slice()) {
            if let RData::DNSSEC(DNSSECRData::NSEC3(n)) = rec.data() {
                let has_type = n.type_bit_maps().any(|t| t == qtype);
                let has_cname = n.type_bit_maps().any(|t| t == RecordType::CNAME);
                let has_soa = n.type_bit_maps().any(|t| t == RecordType::SOA);

                if qtype == RecordType::DS && has_soa {
                    return Some(DnssecStatus::Bogus);
                }

                if !has_type && !has_cname {
                    return Some(DnssecStatus::Secure);
                }
            }
        }
    }
    None
}

fn check_nsec3_wildcard_nodata(
    closest: &Name,
    qtype: RecordType,
    nsec3_records: &[&Record],
    salt: &[u8],
    iterations: u16,
) -> Option<DnssecStatus> {
    let wildcard = wildcard_name(closest);
    let hashed_wildcard = nsec3_hash(&wildcard, salt, iterations);

    let wildcard_rec = nsec3_records
        .iter()
        .find(|&&r| nsec3_owner_hash(r).as_deref() == Some(hashed_wildcard.as_slice()))?;

    if let RData::DNSSEC(DNSSECRData::NSEC3(n)) = wildcard_rec.data() {
        let has_type = n.type_bit_maps().any(|t| t == qtype);
        let has_cname = n.type_bit_maps().any(|t| t == RecordType::CNAME);
        if has_type || has_cname {
            return None;
        }
    } else {
        return None;
    }

    Some(DnssecStatus::Secure)
}

fn check_nsec3_nxdomain(
    qname: &Name,
    closest: &Name,
    qtype: RecordType,
    nsec3_records: &[&Record],
    salt: &[u8],
    iterations: u16,
) -> Option<DnssecStatus> {
    let mut next_closer = qname.clone();
    while next_closer.base_name() != *closest {
        let parent = next_closer.base_name();
        if parent == next_closer {
            return Some(DnssecStatus::Bogus);
        }
        next_closer = parent;
    }
    let hashed_next = nsec3_hash(&next_closer, salt, iterations);

    let covering_rec = nsec3_records
        .iter()
        .find(|&&r| nsec3_covers(r, &hashed_next))?;

    let is_opt_out = match covering_rec.data() {
        RData::DNSSEC(DNSSECRData::NSEC3(n)) => (n.flags() & 0x01) != 0,
        _ => false,
    };

    if is_opt_out && qtype == RecordType::DS {
        tracing::debug!(
            qname = %qname,
            qtype = ?qtype,
            "[DNSSEC] Opt-Out NSEC3 covers next-closer for DS query; proves insecure delegation"
        );
        return Some(DnssecStatus::InsecureUnsigned);
    }

    let wildcard = wildcard_name(closest);
    let hashed_wildcard = nsec3_hash(&wildcard, salt, iterations);
    if !nsec3_records
        .iter()
        .any(|&r| nsec3_covers(r, &hashed_wildcard))
    {
        return Some(DnssecStatus::Bogus);
    }

    Some(DnssecStatus::Secure)
}

fn rrsig_time_valid(sig: &RRSIG, now: u64) -> bool {
    let exp = sig.sig_expiration().get();
    let inc = sig.sig_inception().get();
    let now32 = (now & 0xFFFF_FFFF) as u32;

    (now32.wrapping_sub(inc) as i32) >= 0
        && (exp.wrapping_sub(now32) as i32) >= 0
        && (exp.wrapping_sub(inc) as i32) > 0
}

fn collect_redirection_chain(name: &Name, records: &[Record]) -> RedirectionChainResult {
    let mut chain = Vec::new();
    let mut current = name.clone();
    let mut seen: HashSet<Name> = HashSet::new();

    loop {
        if !seen.insert(current.clone()) {
            return RedirectionChainResult::Loop;
        }
        if chain.len() >= MAX_CNAME_CHAIN {
            return RedirectionChainResult::TooLong;
        }

        let cname_target = records.iter().find_map(|r| {
            if r.name() == &current && r.record_type() == RecordType::CNAME {
                if let RData::CNAME(c) = r.data() {
                    return Some(c.0.clone());
                }
            }
            None
        });

        if let Some(target) = cname_target {
            chain.push(RedirectionStep::Cname {
                owner: current.clone(),
                target: target.clone(),
            });
            current = target;
            continue;
        }

        let dname_step = records.iter().find_map(|r| {
            if r.record_type() == DNAME_RECORD_TYPE
                && r.name().zone_of(&current)
                && r.name() != &current
            {
                let target = extract_dname_target(r)?;
                let sub = dname_substitute(&current, r.name(), &target).ok()?;
                return Some((r.name().clone(), target, sub));
            }
            None
        });

        if let Some((dname_owner, target, redirected_name)) = dname_step {
            chain.push(RedirectionStep::Dname {
                dname_owner,
                target,
                input_name: current.clone(),
                redirected_name: redirected_name.clone(),
            });
            current = redirected_name;
            continue;
        }

        break;
    }

    RedirectionChainResult::Complete(chain)
}

/// Locates the real authoritative zone apex for a name without following CNAMEs
/// to foreign CDN domains.
async fn find_zone_apex(recursor: &RecursiveResolver, name: &Name) -> Option<Name> {
    let mut candidate = name.clone();
    loop {
        if let Ok(msg) = recursor.resolve(&candidate, RecordType::SOA).await {
            // 1. Direct answer: apex returned its own SOA
            for ans in msg.answers() {
                if ans.name() == &candidate && ans.record_type() == RecordType::SOA {
                    return Some(candidate);
                }
            }

            // 2. An apex cannot be a CNAME (RFC 2181 §10.1). If candidate is a CNAME,
            // it is a record, not a zone cut.
            let is_cname = msg
                .answers()
                .iter()
                .any(|r| r.name() == &candidate && r.record_type() == RecordType::CNAME);

            if !is_cname {
                let mut best_soa: Option<Name> = None;
                for rec in msg.answers().iter().chain(msg.name_servers().iter()) {
                    if matches!(rec.data(), RData::SOA(_)) {
                        let soa_name = rec.name();
                        // The SOA MUST be an ancestor suffix of our original query name!
                        // This prevents foreign CNAME targets (like cloudflare.net) from hijacking the zone identity.
                        if soa_name == name || soa_name.zone_of(name) {
                            let is_better = match &best_soa {
                                Some(current) => soa_name.num_labels() > current.num_labels(),
                                None => true,
                            };
                            if is_better {
                                best_soa = Some(soa_name.clone());
                            }
                        }
                    }
                }
                if let Some(soa) = best_soa {
                    return Some(soa);
                }
            }
        }

        if candidate.is_root() {
            break;
        }
        candidate = candidate.base_name();
    }
    None
}

async fn is_zone_signed(
    recursor: &RecursiveResolver,
    name: &Name,
    budget: &mut ValidationBudget,
) -> ZoneSignedness {
    let cache = signed_zone_cache();

    // 1. Check cache: if any ancestor zone is ProvenUnsigned, all descendants are ProvenUnsigned.
    let mut cur = name.clone();
    loop {
        let key = cur.to_string().to_lowercase();
        if let Some(entry) = cache.get(&key) {
            if entry.expires_at > now_secs() {
                match entry.signedness {
                    ZoneSignedness::ProvenUnsigned => return ZoneSignedness::ProvenUnsigned,
                    ZoneSignedness::Signed => {
                        if cur == *name {
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

    // 2. Discover the true authoritative zone apex for `name`
    let zone = match find_zone_apex(recursor, name).await {
        Some(z) => z,
        None => {
            if name.is_root() {
                Name::root()
            } else {
                name.base_name()
            }
        }
    };

    // 3. Authenticate the delegation trust chain from the root down to the discovered apex
    let (signedness, proof_ttl) =
        match DnssecValidator::build_trust_chain(recursor, &zone, budget).await {
            ChainResult::Trusted { ttl, .. } => (ZoneSignedness::Signed, ttl),
            ChainResult::Unsigned { ttl } => (ZoneSignedness::ProvenUnsigned, ttl),
            ChainResult::Bogus => (ZoneSignedness::Unknown, 0),
        };

    if signedness != ZoneSignedness::Unknown {
        cache.insert(
            zone.to_string().to_lowercase(),
            SignedZoneEntry {
                signedness,
                expires_at: now_secs() + proof_ttl.min(86400) as u64,
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

fn wildcard_name(closest: &Name) -> Name {
    if closest.is_root() {
        Name::from_str("*.").unwrap_or_else(|_| Name::root())
    } else {
        let base = closest.to_ascii();
        let base = base.trim_end_matches('.');
        Name::from_str(&format!("*.{}.", base)).unwrap_or_else(|_| Name::root())
    }
}

fn nsec_covers(owner: &Name, next: &Name, target: &Name) -> bool {
    let o = owner.to_lowercase();
    let n = next.to_lowercase();
    let t = target.to_lowercase();

    if o < n {
        o < t && t < n
    } else {
        o < t || t < n
    }
}

fn nsec3_owner_hash(rec: &Record) -> Option<Vec<u8>> {
    let s = rec.name().to_string();
    let first_label = s.trim_end_matches('.').split('.').next()?;
    let hash = base32hex_decode(first_label)?;
    if hash.len() != 20 {
        return None;
    }
    Some(hash)
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
        let bytes: &[u8] = label;
        wire.push(bytes.len() as u8);
        wire.extend_from_slice(&bytes.to_ascii_lowercase());
    }
    wire.push(0);

    wire.extend_from_slice(salt);
    let mut hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &wire)
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
        owner.emit(&mut encoder).ok()?;
        dnskey.emit(&mut encoder).ok()?;
    }
    match digest_type {
        2 => Some(Sha256::digest(&buf).to_vec()),
        4 => Some(Sha384::digest(&buf).to_vec()),
        _ => None,
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| s.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
        .collect()
}

fn build_tbs(rrsig: &RRSIG, owner: &Name, records: &[Record]) -> Option<Vec<u8>> {
    if records.is_empty() {
        return None;
    }

    let expected_type = rrsig.type_covered();
    let expected_class = records[0].dns_class();
    for rec in records {
        if rec.record_type() != expected_type
            || rec.dns_class() != expected_class
            || rec.name() != owner
        {
            return None;
        }
    }

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
        let canonical_signer = rrsig.signer_name().to_lowercase();
        canonical_signer.emit(&mut encoder).ok()?;
        out.extend_from_slice(&name_buf);
    }

    let sig_labels = rrsig.num_labels() as usize;
    let owner_labels = owner.num_labels() as usize;

    let canonical_owner_raw = if owner_labels > sig_labels {
        let base = owner.trim_to(sig_labels);
        Name::from_str(&format!("*.{}", base)).unwrap_or_else(|_| owner.clone())
    } else {
        owner.clone()
    };

    let canonical_owner = canonical_owner_raw.to_lowercase();

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
            let verify_alg: &'static signature::RsaParameters = if algorithm == Algorithm::RSASHA256
            {
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
    if modulus.is_empty() || modulus.len() < 256 || modulus.len() > 1024 {
        return None;
    }
    Some((exponent, modulus))
}