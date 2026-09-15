# Unified Recursive DNS Server

A high-performance, lightweight, multi-protocol recursive DNS resolver engineered in Rust. It serves plain DNS (UDP/TCP), DNS-over-TLS (DoT), and DNS-over-HTTPS (DoH) concurrently while performing independent, from-the-root iterative resolution without relying on upstream third-party resolvers (such as Google, Cloudflare, or Quad9).

Built with production-grade security, comprehensive DNSSEC validation (including authenticated denial of existence, authenticated DS denial, RFC 6672 DNAME synthesis, and post-quantum ML-DSA-44), anti-amplification defenses, SSRF immunity, and an RFC 8767 stale-while-revalidate caching engine with dynamic TTL aging.

---

## Architecture & Request Pipeline

All inbound transports (UDP, TCP, DoT, DoH) share a single, unified resolution and response-construction pipeline. There are no transport-specific hacks for DNSSEC validation or `AD` bit semantics.

```text
                       Client Query
       (Plain UDP/TCP :53, DoT :853, DoH :443/:3053)
                            │
                            ▼
              Inbound Transport & Framing
    (RFC 7766 64KB TCP framing, RFC 8484 HTTP negotiation)
                            │
                            ▼
               Request Parsing & Rate Limiting
      (Subnet token bucket, UDP duplicate-domain RRL, ANY drop)
                            │
                            ▼
              Cache / Recursive Resolution
       (Canonical cache lookup -> Iterative Root Walk)
                            │
                            ▼
                 DNSSEC Validation Engine
    (Trust chain, KSK/ZSK, NSEC/NSEC3 denial, ML-DSA-44 / classical)
                            │
                            ▼
               Canonical Validated Data
           ({qname}:{qtype}:IN canonical cache)
                            │
                            ▼
       Client-Specific Response Construction Pipeline
 ┌─────────────────────────────────────────────────────────────┐
 │ 1. Decrement record TTLs based on elapsed age (RFC 2181)    │
 │    (Original TTL in RRSIG RDATA and OPT records untouched)  │
 │ 2. Apply client Transaction ID and echo RD / CD flags       │
 │ 3. Determine AD flag (RFC 4035 §3.2.3, RFC 6840 §5.7)       │
 │    (Strictly AD=0 if served stale per RFC 8767 §6)          │
 │ 4. Filter DNSSEC records if DO=0 (RFC 4035 §3.2.1)          │
 │ 5. Construct client EDNS0 OPT record (or omit if no EDNS)   │
 │ 6. Set RA=1, AA=0, and serialize wire response              │
 └─────────────────────────────────────────────────────────────┘
                            │
                            ▼
                     Client Response
```

---

## Features & Protocols

### Multi-Protocol Transport
* **Concurrent Protocol Serving**: Simultaneously accepts plain UDP/TCP queries on port 53, DNS-over-TLS (DoT) on port 853 with ALPN `dot`, and DNS-over-HTTPS (DoH) via HTTP/1.1 and HTTP/2 on port 443 in a single runtime.
* **Strict RFC 8484 DoH Implementation**:
  * Supports both `GET` (base64url query parameter) and `POST` (binary `application/dns-message` body).
  * Distinguishes client-side malformed wire format (**HTTP 400 Bad Request**) from valid queries resulting in resolution errors (**HTTP 200 OK** carrying `RCODE=SERVFAIL` wire data).
  * Requires `Content-Type: application/dns-message` on POST requests, rejecting missing or invalid types with **HTTP 415 Unsupported Media Type**.
  * Rejects rate-limited queries with **HTTP 429 Too Many Requests**.
* **RFC 7858 & RFC 7766 TCP/DoT Framing**:
  * Implements standard 2-byte big-endian framing supporting payloads up to **65,535 bytes (64 KB)**, accommodating large post-quantum DNSSEC responses.
  * Supports multi-query pipelining and persistent connection reuse across both plain TCP and TLS sessions.
  * Enforces a 10-second idle timeout and a 5-second active I/O timeout to prevent connection starvation.
* **Reverse-Proxy Ready (DoH Offload)**: Supports unencrypted HTTP backend mode (`DOH_NO_TLS=1`) for local deployment behind reverse proxies like Nginx or Caddy.
* **Auto-Generating Dev Certificates**: Automatically generates a self-signed development certificate on startup using `rcgen` (securing the private key with `0600` permissions on Unix) if existing PEM files are not found.
* **Unprivileged Port Fallbacks**: Automatically falls back to high ports (DNS: `5053`, DoT: `8853`, DoH: `8443`) if started without `root` privileges or `CAP_NET_BIND_SERVICE`.
* **Bounded Concurrency**: Governed by Tokio semaphores (2048 UDP permits, 512 TCP permits, 512 DoT permits) to prevent file descriptor exhaustion.

### Iterative Root Recursion
* **Autonomous Resolution**: Queries authoritative nameservers iteratively starting from the 13 IANA root nameserver clusters (`a.root-servers.net` through `m.root-servers.net`).
* **RFC 6891 §7 EDNS Fallback Workaround**: Automatically detects non-compliant authoritative servers (such as `dnsleaktest.com`) that send malformed `OPT` records or `FORMERR` under EDNS0, seamlessly retrying with plain RFC 1035 DNS to guarantee resolution without compromising security.
* **Strict Answer & Redirection QNAME Matching**: Positively matched answers, CNAME aliases, and DNAME redirections must belong to the exact queried name (`r.name() == name`), blocking cross-domain response injection.
* **Full DNAME Redirection Support (RFC 6672)**: Detects delegation name (`DNAME`, Type 39) records, performs canonical suffix replacement (`dname_substitute`), enforces RFC 6672 length bounds (returning `YXDOMAIN` if a synthesized name exceeds 255 octets), and merges redirection chains.
* **Strict Bailiwick Glue Rules (RFC 2181 §5.4.1)**: Additional records are only accepted as authoritative glue if they belong to an advertised nameserver and are in-bailiwick of the answering zone (or under the delegated child zone). Out-of-bailiwick addresses are rejected as untrusted hints and resolved independently, preventing Kaminsky/Kashpureff glue-poisoning attacks.
* **Dual-Stack Nameserver Resolution**: If upstream delegation glue is omitted, the recursor iteratively resolves both `A` and `AAAA` records for authoritative nameservers to maintain connectivity with IPv6-only authoritative hosts.
* **Referral Coherence & Forward Progress**: Enforces NS owner coherence across referral authority sections; mixed delegation owners or lateral loops abort as `NoProgress`.
* **Parallel Nameserver Racing**: Queries upstream authoritative servers in batches of 3 concurrently, taking the fastest valid response.
* **Upstream Response Classification & Failover (RFC 8906 / BCP 145)**: Treats `FORMERR` and `NOTIMP` as authoritative server failures alongside `SERVFAIL` and `REFUSED`, failing over to remaining nameservers in the batch. Only clean `NOERROR` and `NXDOMAIN` responses terminate server racing.
* **Whole-Transaction TCP Timeout (Anti-Slowloris)**: Connect, write, length read, and payload read operations are collectively wrapped in a unified `timeout(TCP_TIMEOUT, ...)` block (2500ms) to eliminate resource starvation from stalling authoritative servers.
* **Buffer Clamping (DNS Flag Day Compliance)**: Requests 1232-byte EDNS0 payload limits to avoid IP packet fragmentation over the public internet. Truncated responses (`TC=1`) automatically retry over TCP.
* **Recursion Loop Protection**: Caps resolution depth (`MAX_DEPTH = 16`), resolution steps (`MAX_STEPS = 16`), and redirection hops (`MAX_CNAME_CHAIN = 16`) with cycle detection.
* **Parent-Zone Aware DS Lookup**: `DS` queries are dispatched to the *parent* nameservers, not the child's, matching the DNSSEC chain-of-trust delegation model (RFC 4035 §5.2).

### Cryptographic DNSSEC Engine (Classical & Post-Quantum)
* **Full Trust Chain Validation**: Walks the chain of trust top-down from hardcoded root anchors down through DS and DNSKEY records to authenticate RRSIGs.
* **Current Root Anchors**: Built-in verification for root KSK-2017 (Key Tag `20326`) and root KSK-2024 (Key Tag `38696`). Fails closed (`SERVFAIL`) on broken trust chains when enforcement is enabled.
* **Triple-Backend Verification Architecture**:
  * **Optimized Classical Engine (`ring`)**: Hardware-accelerated verification for RSA (`RSASHA256`, `RSASHA512`, strictly bounded to 2048–8192 bits), ECDSA (`ECDSAP256SHA256`, `ECDSAP384SHA384`), and Ed25519 (`ED25519`).
  * **Post-Quantum Engine (`ml-dsa` / RustCrypto)**: Full FIPS 204 verification for ML-DSA-44 (`Algorithm 18`), bypassing `hickory-proto`'s `PublicKey` abstraction which does not implement Algorithm 18.
  * **Native Protocol Fallback (`hickory-proto`)**: Delegation to Hickory's cryptographic verifier for any remaining algorithm suites.
* **Post-Quantum Cryptography (ML-DSA-44 / Algorithm 18)**: Full cryptographic validation of ML-DSA-44 lattice signatures per **NIST FIPS 204** and **draft-ietf-dnsop-ml-dsa-dnssec**. Zones signed exclusively with Algorithm 18 validate with `AD=1`; forged, expired, or missing signatures are rejected with `SERVFAIL`.
* **RFC 4035 §5.2 KSK/ZSK Trust Model & Zone Key Filtering**: Validates the child DNSKEY RRset using parent DS-matched keys (KSKs). Authenticates all keys in the validated RRset possessing the `Zone Key` flag (bit 7 = 1) for subsequent zone record verification. Keys lacking the Zone Key flag cannot authenticate zone data.
* **RFC 4034 §6.2 Canonical Wire Serialization & Case Normalization**: Guarantees that all domain names (both RR member owner names and RRSIG signer names) are converted to lowercase in the wire-format buffer prior to TBS digest calculation. Prevents digest verification failures on uppercase Base32hex NSEC3 owner names (common in `.com` and `.net` registries).
* **Authenticated Denial of DS Nonexistence (Anti-Downgrade)**: If a parent zone returns DS NODATA or NXDOMAIN, the resolver **does not** assume the child is unsigned. It cryptographically authenticates the parent's NSEC or NSEC3 denial-of-existence proof using the parent's DNSKEYs. Only an authenticated denial permits a transition to `InsecureUnsigned`; missing, forged, or unauthenticated DS denial proofs are declared `Bogus` → `SERVFAIL`. This defeats on-path DS-stripping downgrade attacks.
* **Per-Resolution Cryptographic Work Budget (KeyTrap / CVE-2023-50387)**: Operates a thread-safe, unified `ValidationBudget` (`GLOBAL_MAX_SIG_CHECKS = 24`) shared across positive validations, negative proofs, DS verifications, and DNSKEY self-signatures for a given query, preventing CPU-exhaustion DoS from complex key/signature combinatorial attacks.
* **Centralized Signature Time Validation**: Enforces inception and expiration boundaries (`now >= inc && now <= exp`) centrally within `verify_rrsig()`. All validation callers (answer RRsets, NSEC/NSEC3 records, parent DS records, DNSKEY sets) uniformly enforce time boundaries, eliminating negative-proof replay and stale key vulnerabilities.
* **Rollover Availability & Signer Isolation**: In `validate_rrset()`, an expired or unauthorized signature does not cause an immediate `Bogus` failure. The validator evaluates all candidate signatures and only fails closed if zero authorized, time-valid signatures verify against a trusted anchor.
* **Algorithm Parity Enforcement**: Rejects signatures where the RRSIG algorithm does not strictly match the corresponding DNSKEY algorithm (`rrsig.algorithm() == dnskey.algorithm()`).
* **RFC 6672 DNAME Redirection Validation**: Cryptographically verifies the DNAME RRset and any accompanying synthesized CNAME RRset across multi-hop redirection chains with loop and depth limit enforcement.
* **Decomposed NSEC Proof Architecture (RFC 4035 §5.4)**: Decoupled into four distinct proof models:
  * **Direct NODATA**: Verifies matching owner, ensures `qtype` and `CNAME` bits are absent, and ensures `SOA` is absent for DS queries.
  * **Wildcard NODATA**: Confirms the wildcard `*.<closest>` exists, verifies requested types are absent from its bitmap, and proves the exact QNAME is covered.
  * **Direct NXDOMAIN**: Verifies QNAME nonexistence and proves the wildcard `*.<closest>` does not exist.
  * **Wildcard Expansion**: Proves no closer name exists that would have shadowed the wildcard.
* **Decomposed NSEC3 Proof Architecture (RFC 5155 §8)**:
  * **Closest Provable Encloser Walk**: Dedicated ancestor hashing walk (`find_nsec3_closest_provable_encloser`).
  * **RFC 5155 §8.4 Opt-Out Apex Fallback**: For DS queries at an insecure delegation, if the parent registry (e.g. `.org` or `.io`) omits the apex NSEC3 record and only provides the covering Opt-Out record, the closest encloser correctly defaults to the known parent apex (`qname.base_name()`).
  * **RFC 5155 §5 Hash Ordering**: Strictly hashes `wire | salt` (canonical name followed by salt) as required by specification, avoiding hash mismatches on salted registries.
  * **NSEC3 Parameter Consistency**: Enforces identical hash algorithms, iteration counts, and salts across all NSEC3 records participating in a proof.
  * **NSEC3 Opt-Out Handling (RFC 5155 §8.4)**: Evaluates the Opt-Out bit (`flags & 0x01 != 0`). Opt-Out NSEC3 records covering a next-closer name establish an insecure delegation (`InsecureUnsigned`) for DS queries, but are rejected if used to claim authenticated nonexistence (`Secure`) for records within a signed zone.
  * **Hash Length Enforcement**: Validates that decoded base32hex SHA-1 owner hashes are strictly 20 bytes.
* **RFC 9276 NSEC3 Iteration Cap**: NSEC3 records advertising more than 150 hash iterations are rejected as `InsecureUnknown` rather than hashed.
* **RFC 4035 §5.3.4 Wildcard Synthesis**: Accurately detects and synthesizes wildcard labels before canonical digest verification.
* **RFC 4034 §6.3 Canonical Sorting**: Reorders RRset members strictly by canonical RDATA octets prior to digest verification.
* **Full RRset Modeling**: Groups all records sharing the same owner, class, and type into a complete RRset prior to signature verification.

### Caching Engine (RFC 8767 Stale-While-Revalidate & Dynamic TTLs)
* **Client-Agnostic Canonical Storage**: Cache entries are keyed strictly by `{qname}:{qtype}:IN`, storing the canonical validated upstream DNS message. Responses are dynamically adapted to requesting clients on the fly (ID, flags, aged TTLs, DO presentation).
* **Dynamic TTL Aging (RFC 2181)**:
  * Every cached record served to a client has its outer TTL decremented:
    $$\text{remaining\_ttl} = \max(\text{original\_ttl} - \text{age}, 0)$$
  * The cryptographic `Original TTL` inside RRSIG RDATA is preserved untouched for downstream DNSSEC validation.
  * `RecordType::OPT` records are explicitly skipped so EDNS flags/extended RCODE are never corrupted.
* **Typed Cache Freshness Policy**:
  * **`Fresh`** ($\text{age} < \text{TTL}$): Served immediately with aged TTLs.
  * **`Stale`** ($\text{TTL} \le \text{age} < \text{TTL} + \text{MAX\_STALE}$): Served with TTL=0; triggers asynchronous background revalidation. Per RFC 8767 §6, stale responses **strictly set `AD=0`**.
  * **`Expired`** ($\text{age} \ge \text{TTL} + \text{MAX\_STALE}$): **Never served**. Bypasses cache and triggers synchronous iterative resolution. If resolution fails, returns `SERVFAIL` rather than serving zombie records.
* **Configurable Stale Window**: Maximum stale duration is governed by `MAX_STALE_SECS` (default: 300 seconds).
* **Dynamic Zone-Signedness TTL**: Cached zone-signedness entries inherit the authoritative TTL from the validated DNSKEY set or negative DS denial proof, eliminating fixed 5-minute staleness windows when zones transition between signed and unsigned states.
* **Disk Persistence Hygiene**:
  * `load_cache_from_disk()` evaluates the age of all entries on startup; any record exceeding its allowable stale age is purged to prevent zombie record resurrection.
  * `save_cache_to_disk_sync()` prunes expired entries prior to writing JSON storage.
* **Single-Flight Request Deduplication**: Uses an in-flight synchronization registry (`in_flight`) to ensure duplicate background revalidations are never triggered simultaneously for the same RRset.
* **Atomic Disk Persistence**: Asynchronously syncs the in-memory cache to disk every 120 seconds and on clean shutdown using atomic file replacement (`.tmp` write followed by rename).
* **Tranco Cache Pre-warming**: Automatically downloads and unzips the Tranco Top 1M list on startup, populating the cache with canonical validated responses.

### Resolver Hardening & Security
* **SSRF & Reflection Immunity**: Rejects any candidate upstream nameserver IP (from glue or resolved NS records) pointing to:
  * Private networks (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
  * Loopback addresses (`127.0.0.0/8`, `::1`)
  * Link-local and cloud metadata addresses (`169.254.0.0/16`, `fe80::/10`)
  * Carrier-Grade NAT (RFC 6598: `100.64.0.0/10`)
  * Documentation and benchmark ranges (RFC 2544: `198.18.0.0/15`)
  * Broadcast, multicast, unspecified (`0.0.0.0/8`, `::`)
  * IPv6 Unique Local Addresses (`fc00::/7`) and IPv4-mapped IPv6 ranges
* **Spoofed Reverse Proxy Header Protection**: Only trusts reverse-proxy headers (`CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-For`) when the incoming TCP peer is verified to be a local loopback address (`127.0.0.1` or `::1`).
* **Response Normalization & Structure Verification**: Clears upstream `AA`, sets `RA`, echoes client `RD`/`CD`, and verifies single-question constraints with matching `OpCode::Query` on all responses.

### Abuse Defense & Rate Limiting (RRL)
* **Subnet-Aware Token Bucket**: Aggregates traffic by `/24` IPv4 subnets and `/64` IPv6 prefixes. Thread-safe atomic refill ensures lock-free concurrency.
* **Strict Transport Isolation**: Connection-oriented protocols (TCP, DoT, DoH) are governed by the subnet token bucket only, preventing false duplicate-domain penalties on pipelined connections.
* **DNS ANY Drop**: Instantly drops UDP queries requesting type `ANY` to neutralize high-volume amplification vectors (RFC 8482).
* **Adaptive Domain Throttling (UDP only)**:
  * 1st duplicate query in a one-second window: Allowed.
  * 2nd duplicate query: Challenged with `TC=1` (forces client to prove its source IP via TCP handshake).
  * 3rd+ duplicate query: Subject to a 3-second penalty drop.
* **Memory Exhaustion Immunity**: If the tracked RRL domain table reaches capacity (`MAX_TRACKED_RRL_ENTRIES = 65,536`), new domains fall back to standard token bucket processing rather than blackholing global UDP traffic.

---

## Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `HOST` | `0.0.0.0` | Bind IP address for all listeners |
| `DNS_PORT` | `53` | Plain UDP/TCP DNS port (fallback: `5053`) |
| `DOT_PORT` | `853` | DNS-over-TLS port (fallback: `8853`) |
| `DOH_PORT` | `443` | DNS-over-HTTPS port (fallback: `8443`, or backend port like `3053`) |
| `DOH_NO_TLS` | `0` | Set to `1` for plain HTTP backend mode when reverse proxy terminates TLS |
| `DNSSEC_ENFORCE` | `1` | Strictly return `SERVFAIL` on broken DNSSEC chains (`0` returns data with `AD=0`) |
| `MAX_STALE_SECS` | `300` | Maximum window (in seconds) to serve stale records during background revalidation |
| `RATE_LIMIT_BURST` | `300` | Maximum token bucket burst capacity per client subnet |
| `RATE_LIMIT_PER_SEC` | `60` | Sustained refill rate per second per client subnet |
| `CERT_PATH` | `fullchain.pem` | Path to TLS certificate chain |
| `KEY_PATH` | `privkey.pem` | Path to TLS private key |
| `WARM_LIMIT` | `0` | Number of top Tranco domains to pre-warm on launch (`0` to disable) |
| `WARM_CONCURRENCY` | `6` | Concurrency limit for background pre-warming |

---

## Building and Compiling

Ensure Rust (1.78 or newer) and Cargo are installed.

```bash
cargo build --release
```

The compiled binary will be placed at `./target/release/doh-server`.

To grant privileged port binding capabilities to an unprivileged user:
```bash
sudo setcap 'cap_net_bind_service=+ep' ./target/release/doh-server
```

### Post-Quantum Signature Size Note

ML-DSA-44 signatures are 2,420 bytes and public keys are 1,312 bytes. A single Algorithm-18 RRSIG will exceed the 1,232-byte DNS Flag Day EDNS buffer on its own, so every post-quantum query automatically triggers a TCP fallback. This is handled transparently by the recursor's truncation-detection path, but clients should be aware that Algorithm-18 zones will always see a TCP retry.

---

## Deployment Architectures

### Option A: Standalone Deployment (Direct TLS)

Create `/etc/systemd/system/doh-server.service`:

```ini
[Unit]
Description=Unified Recursive DNS Server
After=network.target

[Service]
Type=simple
User=doh
Group=doh
WorkingDirectory=/var/lib/doh-server
ExecStart=/usr/local/bin/doh-server

Environment="HOST=0.0.0.0"
Environment="DNS_PORT=53"
Environment="DOT_PORT=853"
Environment="DOH_PORT=443"
Environment="DOH_NO_TLS=0"
Environment="DNSSEC_ENFORCE=1"
Environment="MAX_STALE_SECS=300"
Environment="RATE_LIMIT_BURST=300"
Environment="RATE_LIMIT_PER_SEC=60"
Environment="CERT_PATH=/etc/letsencrypt/live/dns.example.com/fullchain.pem"
Environment="KEY_PATH=/etc/letsencrypt/live/dns.example.com/privkey.pem"
Environment="WARM_LIMIT=500"
Environment="WARM_CONCURRENCY=8"
Environment="RUST_LOG=info,doh_server=info"

Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now doh-server.service
```

---

### Option B: Reverse Proxy Deployment (Nginx + DoH Backend)

In this architecture, Nginx handles public HTTPS traffic (port 443) and proxies DoH requests to `127.0.0.1:3053` using `DOH_NO_TLS=1`. Plain DNS and DoT continue to run directly on ports 53 and 853.

```nginx
upstream doh_backend {
    server 127.0.0.1:3053;
    keepalive 64;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name dns.example.com;

    ssl_certificate /etc/letsencrypt/live/dns.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dns.example.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    client_max_body_size 10k;

    # RFC 8484 DoH query endpoint
    location = /dns-query {
        proxy_pass http://doh_backend/dns-query;
        proxy_http_version 1.1;

        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Content-Type application/dns-message;

        proxy_buffering off;
        proxy_request_buffering off;
    }

    location = /health {
        proxy_pass http://doh_backend/health;
        proxy_set_header Host $host;
    }
}
```

---

## Verification & Testing

### 1. Plain DNS (UDP & TCP)
```bash
dig @127.0.0.1 -p 53 example.com A +dnssec
dig +tcp @127.0.0.1 -p 53 example.com A +dnssec
```

### 2. DNS-over-TLS (DoT)
```bash
kdig -d @dns.example.com:853 +tls example.com A
```

### 3. DNS-over-HTTPS (DoH)
```bash
# Wireformat query via HTTP POST (RFC 8484)
echo -n "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB" | base64 -d | \
  curl -s -X POST --data-binary @- \
  -H "Content-Type: application/dns-message" \
  -H "Accept: application/dns-message" \
  https://dns.example.com/dns-query | hexdump -C

# Wireformat query via HTTP GET (RFC 8484)
curl -s -H "Accept: application/dns-message" \
  "https://dns.example.com/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB" | hexdump -C
```

### 4. Comprehensive DNSSEC Validation Testing

The resolver achieves a **100% pass rate across all four algorithm suites and all four signature states** on [dnscheck.tools](https://dnscheck.tools/):

* **ECDSA P-256 (alg13)**: Resolves with `AD=1`.
* **ECDSA P-384 (alg14)**: Resolves with `AD=1`.
* **Ed25519 (alg15)**: Resolves with `AD=1`.
* **ML-DSA-44 (alg18)**: Post-quantum signatures resolve with `AD=1`.
* **Tampered (`badsig`), Expired (`expiredsig`), and Unsigned (`nosig`)**: Strictly blocked with `SERVFAIL`.

Test against the standard Comcast DNSSEC failure test domain:
```bash
dig @127.0.0.1 -p 53 dnssec-failed.org A
# Expect status: SERVFAIL
```

Test EDNS fallback handling against non-compliant authoritative servers:
```bash
dig @127.0.0.1 -p 53 dnsleaktest.com A
# Expect status: NOERROR (automatically falls back to plain DNS)
```

---

## Security Mitigations Matrix

| Threat Vector | Mitigation Strategy | Standards Reference |
| :--- | :--- | :--- |
| **DS-Stripping / Insecure Downgrade** | Rejection of empty DS responses unless accompanied by cryptographically verified parent NSEC/NSEC3 denial proofs | RFC 4035 §5.2, RFC 5155 §8.4, RFC 6840 §5.9 |
| **Broken EDNS Authoritative Servers** | Automatic detection of malformed `OPT` records or `FORMERR`; transparent fallback to plain RFC 1035 DNS queries | RFC 6891 §7 |
| **Out-of-Bailiwick Glue Poisoning** | Additional records accepted as glue only if in-bailiwick of the answering server or child zone; all out-of-bailiwick NS hostnames resolved independently | RFC 2181 §5.4.1 |
| **SSRF / Reflection via Glue** | Strict rejection of private, loopback, multicast, link-local, and cloud metadata IPs from glue and resolved NS addresses | RFC 1918, RFC 3927, RFC 6598 |
| **DNS Cache Poisoning & Record Injection** | Strict queried QNAME verification on answers, CNAME, and DNAME records; random TXID; randomized server selection | RFC 5452 |
| **Forged NXDOMAIN / Negative Poisoning** | Decomposed NSEC/NSEC3 state machines for NODATA, Wildcard NODATA, and NXDOMAIN; Opt-Out flag handling; 150-iteration cap | RFC 4035 §5.4, RFC 5155 §8, RFC 9276, CVE-2010-0097 |
| **Authoritative Upstream Misbehavior / Hangs** | Strict response classification (`FORMERR`/`NOTIMP` trigger server failover); unified whole-transaction TCP timeout (2500ms) | RFC 8906, BCP 145 |
| **KeyTrap Algorithmic Complexity** | Per-resolution `ValidationBudget` shared across all lookup stages (capped to 24 signature checks total) | CVE-2023-50387 |
| **DNAME Loop / Suffix Length Overflow** | Bounded redirection chain tracking with cycle detection; RFC 6672 §2.2 name length verification (returning `YXDOMAIN` on overflow) | RFC 6672 |
| **DNSKEY Trust-Boundary Violation** | Strict enforcement of the `Zone Key` flag (bit 7 = 1) on authenticated keys; KSK authenticates full DNSKEY set per RFC 4035 §5.2 | RFC 4034 §2.1.1, RFC 4035 §5.2 |
| **Canonical TBS Wire Digest Mismatch** | Strict lowercase canonicalization of owner names and signer names in wire TBS construction (resolves Base32hex NSEC3 failures) | RFC 4034 §6.2 |
| **DNS Amplification** | Instant drop of UDP `ANY` queries; truncated challenges (`TC=1`) when response size exceeds EDNS payload | RFC 8482 |
| **Volumetric / DoS Floods** | Subnet-aggregated atomic token bucket rate limiting (/24 IPv4, /64 IPv6); RRL memory exhaustion fallback prevents self-inflicted DoS | RFC 5358 |
| **NSEC3 Hash-Ring Forgery** | In-house NSEC3 hash-ring comparison and closest-encloser proof logic, avoiding an upstream advisory in `hickory-proto` 0.25.0..0.26.0-alpha.1 | GHSA-588m-chg6-8jqj |
| **Stale Key Window Over-Extension** | Elimination of minimum TTL clamping floors; dynamic TTL aging on all served records; zone-signedness cache inherits exact dynamic proof TTLs | RFC 2181, RFC 4034, RFC 5011 |
| **Stale DNSSEC Data Persistence** | RFC 8767 §6 enforcement: responses served from stale cache strictly set `AD=0`; expired records beyond `MAX_STALE_SECS` are rejected | RFC 8767 §6 |
| **DoH Protocol Ambiguity** | Strict RFC 8484 mapping: malformed inputs return HTTP 400; missing Content-Type returns HTTP 415; SERVFAIL returns HTTP 200 with wire payload | RFC 8484 |
| **Proxy Header Spoofing** | Proxy headers (`X-Real-IP`, `X-Forwarded-For`, `CF-Connecting-IP`) only evaluated when incoming connection is from loopback | Security Best Practice |
| **Fragmented UDP Poisoning** | Outgoing EDNS buffer clamped to 1232 bytes to eliminate IP fragmentation; automatic TCP fallback for larger responses including all Algorithm-18 replies | DNS Flag Day 2020 |
| **Post-Quantum Signature Malleability** | ML-DSA-44 verification via RustCrypto `ml-dsa` ≥ 0.1.1, which rejects signatures with repeated hint indices (CVE-2026-24850) | CVE-2026-24850 |

---

## License

This project is licensed under the MIT License.
