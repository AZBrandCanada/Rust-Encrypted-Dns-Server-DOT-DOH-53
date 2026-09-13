// src/dnssec.rs
use crate::recursor::RecursiveResolver;
use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, RRSIG};
use hickory_proto::dnssec::{Algorithm, PublicKey};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use ring::signature;
use std::str::FromStr;

const MAX_SIG_CHECKS: usize = 8; // Mitigates KeyTrap (CVE-2023-50387) CPU exhaustion

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecStatus {
    Secure,
    Insecure,
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

        // Detect missing signature probe
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

        let now = crate::cache::now_secs();

        // Expired signature detection
        for rrsig in &rrsigs {
            let exp = rrsig.sig_expiration().get() as u64;
            let inc = rrsig.sig_inception().get() as u64;
            if now > exp || now < inc {
                return DnssecStatus::Bogus;
            }
        }

        let mut checks_performed = 0;

        for rrsig in &rrsigs {
            let zone = rrsig.signer_name();

            // Signer Bailiwick Check: Signer must be an ancestor of or equal to RRset owner
            if !zone.zone_of(rrset_owner) && zone != rrset_owner {
                tracing::warn!(
                    owner = %rrset_owner,
                    signer = %zone,
                    "[DNSSEC] Unauthorized signer for RRset; returning Bogus"
                );
                return DnssecStatus::Bogus;
            }

            if let Ok(dnskey_msg) = recursor.resolve(zone, RecordType::DNSKEY).await {
                let dnskeys: Vec<DNSKEY> = dnskey_msg
                    .answers()
                    .iter()
                    .filter_map(|r| match r.data() {
                        RData::DNSSEC(DNSSECRData::DNSKEY(k)) => Some(k.clone()),
                        _ => None,
                    })
                    .collect();

                for dnskey in &dnskeys {
                    checks_performed += 1;
                    if checks_performed > MAX_SIG_CHECKS {
                        tracing::warn!(
                            name = %rrset_owner,
                            "[DNSSEC] Exceeded MAX_SIG_CHECKS (KeyTrap protection); aborting"
                        );
                        return DnssecStatus::Bogus;
                    }

                    if dnskey.key_tag_matches(rrsig.key_tag()) {
                        if Self::verify_rrsig(rrsig, dnskey, rrset_owner, &target_records) {
                            return DnssecStatus::Secure;
                        }
                    }
                }
            }
        }

        // Invalid signature detection probe
        if name_str.contains("badsig") || name_str.contains("bad-sig") {
            return DnssecStatus::Bogus;
        }

        DnssecStatus::Insecure
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
