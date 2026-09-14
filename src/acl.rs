// src/acl.rs
//
// Recursion access-control list.
//
// Only applied to plain UDP/TCP DNS queries; DoH and DoT are public services
// by design and are not subject to the ACL.
//
// Configured via env vars:
//   ALLOWED_CLIENTS   comma-separated list of CIDRs (or plain IPs)
//                     Default: loopback + RFC1918 + link-local + ULA
//   DISABLE_ACL=1     disable the ACL entirely (allow all clients)
//
// If ALLOWED_CLIENTS parses to zero valid entries, the ACL fails CLOSED
// (all recursion queries are REFUSED) and a loud error is logged.

use std::net::IpAddr;

#[derive(Debug, Clone)]
struct AclEntry {
    network: IpAddr,
    prefix_len: u8,
}

#[derive(Debug, Clone)]
pub struct Acl {
    entries: Vec<AclEntry>,
    default_allow: bool,
}

impl Acl {
    pub fn from_env() -> Self {
        if std::env::var("DISABLE_ACL").ok().as_deref() == Some("1") {
            tracing::warn!(
                "[ACL] DISABLE_ACL=1: recursion ACL disabled, ALL clients allowed on UDP/TCP"
            );
            return Self { entries: Vec::new(), default_allow: true };
        }

        let spec = std::env::var("ALLOWED_CLIENTS").unwrap_or_else(|_| {
            // Safe default: only clients on private/internal networks.
            "127.0.0.0/8,::1/128,\
             10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,\
             169.254.0.0/16,fe80::/10,fc00::/7"
                .to_string()
        });

        let mut entries = Vec::new();
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            match parse_cidr(part) {
                Some(e) => entries.push(e),
                None => tracing::warn!(entry = part, "[ACL] Failed to parse ACL entry"),
            }
        }

        if entries.is_empty() {
            tracing::error!(
                "[ACL] ALLOWED_CLIENTS produced no valid entries; \
                 failing CLOSED. All UDP/TCP recursion queries will be REFUSED."
            );
        } else {
            tracing::info!(
                entries = entries.len(),
                "[ACL] Recursion ACL loaded (UDP/TCP only)"
            );
        }

        Self { entries, default_allow: false }
    }

    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        if self.default_allow {
            return true;
        }
        // Normalize IPv4-mapped IPv6 so `::ffff:10.0.0.1` matches `10.0.0.0/8`.
        let ip = normalize_ip(ip);
        self.entries
            .iter()
            .any(|e| cidr_contains(&e.network, e.prefix_len, &ip))
    }
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return IpAddr::V4(v4);
        }
    }
    ip
}

fn parse_cidr(s: &str) -> Option<AclEntry> {
    let (ip_part, prefix_part) = match s.split_once('/') {
        Some((a, b)) => (a, b.parse::<u8>().ok()?),
        None => (s, if s.contains(':') { 128 } else { 32 }),
    };
    let ip: IpAddr = ip_part.parse().ok()?;
    let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
    if prefix_part > max_prefix {
        return None;
    }
    Some(AclEntry { network: ip, prefix_len: prefix_part })
}

fn cidr_contains(network: &IpAddr, prefix_len: u8, ip: &IpAddr) -> bool {
    match (network, ip) {
        (IpAddr::V4(net), IpAddr::V4(check)) => {
            let net_bits = u32::from_be_bytes(net.octets());
            let check_bits = u32::from_be_bytes(check.octets());
            let mask: u32 = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_len as u32)
            };
            (net_bits & mask) == (check_bits & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(check)) => {
            let net_bits = u128::from_be_bytes(net.octets());
            let check_bits = u128::from_be_bytes(check.octets());
            let mask: u128 = if prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - prefix_len as u32)
            };
            (net_bits & mask) == (check_bits & mask)
        }
        _ => false,
    }
}