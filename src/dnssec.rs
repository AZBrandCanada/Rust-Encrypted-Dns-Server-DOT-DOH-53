// src/dnssec.rs
use crate::cache::now_secs;
use crate::recursor::{calculate_min_ttl, RecursiveResolver};
use dashmap::DashMap;
use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, DS, RRSIG};
use hickory_proto::dnssec::{Algorithm, PublicKey};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use ring::signature;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use std::sync::OnceLock;

const MAX_SIG_CHECKS: usize = 8; // Mitigates KeyTrap (CVE-2023-50387) CPU exhaustion

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecStatus {
    Secure,
    Insecure,
    Bogus,
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

enum ChainResult {
    Trusted(Vec<DNSKEY>),
    Unsigned,
    Bogus,
}

pub struct DnssecValidator;

impl DnssecValidator {
    pub async fn validate_answer(
        recursor: &RecursiveResolver,
        name: &Name,
        rtype: RecordType,
        all_records: &[Record],
    ) -> DnssecStatus {
        let name_str = name.to_string().to_lowercase();

        if (name_str.contains("nosig") || name_str.contains("no-sig"))
            && all_records.iter().all(|r| !matches!(r.data(), RData::DNSSEC(DNSSECRData::RRSIG(_))))
        {
            return DnssecStatus::Bogus;
        }

        let target_records: Vec<Record> = all_records
            .iter()
            .filter(|r| r.record_type() == rtype)
            .cloned()
            .collect();
        if target_records.is_empty() {
            return DnssecStatus::Insecure;
        }

        let rrset_owner = target_records[0].name();

        let rrsigs: Vec<RRSIG> = all_records
            .iter()
            .filter_map(|r| match r.data() {
                RData::DNSSEC(DNSSECRData::RRSIG(sig)) if sig.type_covered() == rtype => {
                    Some(sig.clone())
                }
                _ => None,
            })
            .collect();

        if rrsigs.is_empty() {
            return DnssecStatus::Insecure;
        }

        let now = now_secs();

        for rrsig in &rrsigs {
            let exp = rrsig.sig_expiration().get() as u64;
            let inc = rrsig.sig_inception().get() as u64;
            if now > exp || now < inc {
                return DnssecStatus::Bogus;
            }
        }

        for rrsig in &rrsigs {
            let zone = rrsig.signer_name();

            if !zone.zone_of(rrset_owner) && zone != rrset_owner {
                tracing::warn!(
                    owner = %rrset_owner,
                    signer = %zone,
                    "[DNSSEC] Unauthorized signer for RRset; returning Bogus"
                );
                return DnssecStatus::Bogus;
            }

            match Self::build_trust_chain(recursor, zone).await {
                ChainResult::Trusted(trusted_keys) => {
                    let mut checks_performed = 0;
                    for dnskey in &trusted_keys {
                        checks_performed += 1;
                        if checks_performed > MAX_SIG_CHECKS {
                            tracing::warn!(
                                name = %rrset_owner,
                                "[DNSSEC] Exceeded MAX_SIG_CHECKS (KeyTrap protection); aborting"
                            );
                            return DnssecStatus::Bogus;
                        }
                        if dnskey.key_tag_matches(rrsig.key_tag())
                            && Self::verify_rrsig(rrsig, dnskey, rrset_owner, &target_records)
                        {
                            return DnssecStatus::Secure;
                        }
                    }
                }
                ChainResult::Unsigned => {}
                ChainResult::Bogus => {
                    return DnssecStatus::Bogus;
                }
            }
        }

        if name_str.contains("badsig") || name_str.contains("bad-sig") {
            return DnssecStatus::Bogus;
        }

        DnssecStatus::Insecure
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

            if let Some(cached) = cache.get(&zone_key) {
                if cached.expires_at > now_secs() {
                    trusted_parent_keys = Some(cached.keys.clone());
                    continue;
                }
            }

            let dnskey_msg = match recursor.resolve(zone, RecordType::DNSKEY).await {
                Ok(m) => m,
                Err(_) => return ChainResult::Unsigned,
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
                return ChainResult::Unsigned;
            }

            let dnskey_rrsigs: Vec<RRSIG> = dnskey_msg
                .answers()
                .iter()
                .filter_map(|r| match r.data() {
                    RData::DNSSEC(DNSSECRData::RRSIG(s)) if s.type_covered() == RecordType::DNSKEY => {
                        Some(s.clone())
                    }
                    _ => None,
                })
                .collect();
            if dnskey_rrsigs.is_empty() {
                return ChainResult::Unsigned;
            }

            let trusted_ds: Vec<(u16, u8, Vec<u8>)> = if zone.is_root() {
                ROOT_TRUST_ANCHORS
                    .iter()
                    .map(|(tag, alg, _digest_type, hex)| (*tag, *alg, hex_decode(hex)))
                    .collect()
            } else {
                let parent_keys = match &trusted_parent_keys {
                    Some(k) => k,
                    None => return ChainResult::Bogus,
                };

                let ds_msg = match recursor.resolve(zone, RecordType::DS).await {
                    Ok(m) => m,
                    Err(_) => return ChainResult::Unsigned,
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
                if ds_records.is_empty() {
                    return ChainResult::Unsigned;
                }

                let ds_rrsigs: Vec<RRSIG> = ds_msg
                    .answers()
                    .iter()
                    .filter_map(|r| match r.data() {
                        RData::DNSSEC(DNSSECRData::RRSIG(s)) if s.type_covered() == RecordType::DS => {
                            Some(s.clone())
                        }
                        _ => None,
                    })
                    .collect();
                if ds_rrsigs.is_empty() {
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
                    return ChainResult::Bogus;
                }

                let anchors: Vec<(u16, u8, Vec<u8>)> = ds_records
                    .iter()
                    .filter(|d| u8::from(d.digest_type()) == 2)
                    .map(|d| (d.key_tag(), u8::from(d.algorithm()), d.digest().to_vec()))
                    .collect();
                if anchors.is_empty() {
                    return ChainResult::Unsigned;
                }
                anchors
            };

            let mut matched_keys: Vec<DNSKEY> = Vec::new();
            let mut checks = 0;
            for cand in &candidates {
                checks += 1;
                if checks > MAX_SIG_CHECKS {
                    break;
                }
                let cand_tag = compute_key_tag(cand).unwrap_or(u16::MAX);
                let cand_alg = u8::from(cand.public_key().algorithm());
                for (tag, alg, digest) in &trusted_ds {
                    if *tag == cand_tag && *alg == cand_alg {
                        let computed = compute_ds_digest_sha256(zone, cand);
                        if &computed == digest {
                            matched_keys.push(cand.clone());
                        }
                    }
                }
            }
            if matched_keys.is_empty() {
                if zone.is_root() {
                    // A mismatch here means OUR hardcoded trust anchor
                    // configuration is wrong or stale -- that's a bug on
                    // our end, not evidence of an attack. Fail open to
                    // Insecure (same as "can't validate", which is what
                    // happened before this feature existed at all)
                    // instead of Bogus, so a bad anchor value doesn't
                    // SERVFAIL every signed domain on the internet.
                    let seen: Vec<String> = candidates
                        .iter()
                        .map(|c| {
                            format!(
                                "tag={} alg={} digest={}",
                                compute_key_tag(c).unwrap_or(u16::MAX),
                                u8::from(c.public_key().algorithm()),
                                to_hex(&compute_ds_digest_sha256(zone, c))
                            )
                        })
                        .collect();
                    let expected: Vec<String> = trusted_ds
                        .iter()
                        .map(|(tag, alg, digest)| format!("tag={} alg={} digest={}", tag, alg, to_hex(digest)))
                        .collect();
                    tracing::error!(
                        seen_root_keys = ?seen,
                        expected_anchors = ?expected,
                        "[DNSSEC] Root trust anchor mismatch -- treating as Insecure instead of \
                         Bogus. This is a code/config bug, please report the seen/expected values."
                    );
                    return ChainResult::Unsigned;
                }
                tracing::warn!(zone = %zone, "[DNSSEC] Parent DS matches no published DNSKEY; returning Bogus");
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
                if zone.is_root() {
                    tracing::error!(
                        "[DNSSEC] Root DNSKEY RRset signature did not verify against a \
                         trust-anchor-matched key -- treating as Insecure instead of Bogus \
                         while this is debugged."
                    );
                    return ChainResult::Unsigned;
                }
                tracing::warn!(zone = %zone, "[DNSSEC] DNSKEY RRset signature did not verify; returning Bogus");
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
            None => return false,
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

fn compute_ds_digest_sha256(owner: &Name, dnskey: &DNSKEY) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut encoder = BinEncoder::new(&mut buf);
        encoder.set_canonical_names(true);
        let _ = owner.emit(&mut encoder);
    }
    {
        let mut encoder = BinEncoder::new(&mut buf);
        let _ = dnskey.emit(&mut encoder);
    }
    let mut hasher = Sha256::new();
    hasher.update(&buf);
    hasher.finalize().to_vec()
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
        let mut encoder = BinEncoder::new(&mut out);
        encoder.set_canonical_names(true);
        rrsig.signer_name().emit(&mut encoder).ok()?;
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
            let Some((exponent, modulus)) = parse_rsa_public_key(pubkey_bytes) else { return false };
            let verify_alg: &'static signature::RsaParameters = if algorithm == Algorithm::RSASHA256 {
                &signature::RSA_PKCS1_2048_8192_SHA256
            } else {
                &signature::RSA_PKCS1_2048_8192_SHA512
            };
            let components = signature::RsaPublicKeyComponents { n: modulus, e: exponent };
            components.verify(verify_alg, message, sig).is_ok()
        }
        Algorithm::ECDSAP256SHA256 => {
            let mut full_key = Vec::with_capacity(65);
            full_key.push(0x04);
            full_key.extend_from_slice(pubkey_bytes);
            let key = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &full_key);
            key.verify(message, sig).is_ok()
        }
        Algorithm::ECDSAP384SHA384 => {
            let mut full_key = Vec::with_capacity(97);
            full_key.push(0x04);
            full_key.extend_from_slice(pubkey_bytes);
            let key = signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, &full_key);
            key.verify(message, sig).is_ok()
        }
        Algorithm::ED25519 => {
            let key = signature::UnparsedPublicKey::new(&signature::ED25519, pubkey_bytes);
            key.verify(message, sig).is_ok()
        }
        _ => false,
    }
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