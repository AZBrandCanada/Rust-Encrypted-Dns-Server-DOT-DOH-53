# Unified Recursive DNS Server

A high-performance, lightweight, multi-protocol recursive DNS resolver engineered in Rust. It serves plain DNS (UDP/TCP), DNS-over-TLS (DoT), and DNS-over-HTTPS (DoH) concurrently while performing independent, from-the-root iterative resolution without relying on upstream third-party resolvers (such as Google, Cloudflare, or Quad9).

Built with production-grade security, comprehensive DNSSEC validation (including authenticated denial of existence, authenticated DS denial, RFC 6672 DNAME synthesis, and post-quantum ML-DSA-44), anti-amplification defenses, SSRF immunity, and a stale-while-revalidate caching engine.

---

## Features & Architecture

### Multi-Protocol Transport
* **Concurrent Protocol Serving**: Simultaneously accepts plain UDP/TCP queries on port 53, DNS-over-TLS (DoT) on port 853 with ALPN `dot`, and DNS-over-HTTPS (DoH) via HTTP/1.1 and HTTP/2 on port 443 in a single runtime.
* **Reverse-Proxy Ready (DoH Offload)**: Supports unencrypted HTTP backend mode (`DOH_NO_TLS=1`) for local deployment behind reverse proxies like Nginx or Caddy, eliminating double-TLS overhead.
* **Auto-Generating Dev Certificates**: Automatically generates a self-signed development certificate on startup using `rcgen` (securing the private key with `0600` permissions on Unix) if existing PEM files are not found.
* **Unprivileged Port Fallbacks**: Automatically falls back to high ports (DNS: `5053`, DoT: `8853`, DoH: `8443`) if started without `root` privileges or `CAP_NET_BIND_SERVICE`.
* **Bounded Concurrency & Timeouts**: Governed by Tokio semaphores (2048 UDP permits, 512 TCP permits, 512 DoT permits) and strict 5-second stream timeouts to prevent file descriptor exhaustion.

### Iterative Root Recursion
* **Autonomous Resolution**: Queries authoritative nameservers iteratively starting from the 13 IANA root nameserver clusters (`a.root-servers.net` through `m.root-servers.net`).
* **Strict Answer & Redirection QNAME Matching**: Positively matched answers, CNAME aliases, and DNAME redirections must belong to the exact queried name (`r.name() == name`). Out-of-bailiwick or mismatched records in the answer section are rejected, blocking cross-domain response injection and cache poisoning.
* **Upstream Response Classification & Failover (RFC 8906 / BCP 145)**: The resolver treats `FORMERR` and `NOTIMP` as authoritative server failures alongside `SERVFAIL` and `REFUSED`, automatically failing over to remaining nameservers in the batch rather than accepting protocol errors as terminal answers. Only clean `NOERROR` and `NXDOMAIN` responses terminate server racing.
* **Full DNAME Redirection Support (RFC 6672)**: Detects delegation name (`DNAME`, Type 39) records, performs canonical suffix replacement (`dname_substitute`), iteratively resolves the redirected target domain, and merges answers seamlessly.
* **Dual-Stack Nameserver Resolution**: If upstream delegation glue is omitted, the recursor iteratively resolves both `A` and `AAAA` records for authoritative nameservers to maintain full connectivity with IPv6-only authoritative hosts.
* **Referral Coherence & Bailiwick Verification**: Validates delegation hierarchy and bailiwick boundaries. Enforces NS owner coherence across referral authority sections; mixed or conflicting delegation owners abort the step as `NoProgress`.
* **Parallel Nameserver Racing**: Queries upstream authoritative servers in batches of 3 concurrently, taking the fastest valid response to eliminate tail latencies from unresponsive servers.
* **Whole-Transaction TCP Timeout (Anti-Slowloris)**: Connect, write, 2-byte frame-length read, and full payload read operations are collectively wrapped in a unified `timeout(TCP_TIMEOUT, ...)` block (2500ms) to eliminate resource starvation from stalling authoritative servers.
* **Buffer Clamping (DNS Flag Day Compliance)**: Requests 1232-byte EDNS0 payload limits to avoid IP packet fragmentation over the public internet. Truncated responses (`TC=1`) or responses larger than the buffer automatically retry over TCP.
* **Recursion Loop Protection**: Caps resolution depth (`MAX_DEPTH = 16`), resolution steps (`MAX_STEPS = 16`), and redirection hops (`MAX_CNAME_CHAIN = 16`) with cycle detection to abort cyclic CNAME/DNAME loops.
* **Parent-Zone Aware DS Lookup**: `DS` queries are dispatched to the *parent* nameservers, not the child's, matching the DNSSEC chain-of-trust delegation model (RFC 4035 §5.2).

### Cryptographic DNSSEC Engine (Classical & Post-Quantum)
* **Full Trust Chain Validation**: Walks the chain of trust top-down from hardcoded root anchors down through DS and DNSKEY records to authenticate RRSIGs.
* **Current Root Anchors**: Built-in verification for root KSK-2017 (Key Tag `20326`) and root KSK-2024 (Key Tag `38696`).
* **Triple-Backend Verification Architecture**:
  * **Optimized Classical Engine (`ring`)**: Hardware-accelerated verification for RSA (`RSASHA256`, `RSASHA512`, strictly bounded to 2048–8192 bits), ECDSA (`ECDSAP256SHA256`, `ECDSAP384SHA384`), and Ed25519 (`ED25519`).
  * **Post-Quantum Engine (`ml-dsa` / RustCrypto)**: Full FIPS 204 verification for ML-DSA-44 (`Algorithm 18`), bypassing `hickory-proto`'s `PublicKey` abstraction which does not implement Algorithm 18.
  * **Native Protocol Fallback (`hickory-proto`)**: Delegation to Hickory's cryptographic verifier for any remaining algorithm suites.
* **Post-Quantum Cryptography (ML-DSA-44 / Algorithm 18)**: Full cryptographic validation of ML-DSA-44 lattice signatures per **NIST FIPS 204** and **draft-ietf-dnsop-ml-dsa-dnssec**. Zones signed exclusively with Algorithm 18 validate with `AD=1`; forged, expired, or missing signatures are rejected with `SERVFAIL`.
* **RFC 4035 §5.2 KSK/ZSK Trust Hierarchy & Zone Key Filtering**: Validates the child DNSKEY RRset using parent DS-matched keys (KSKs), and authenticates all keys in the validated RRset possessing the `Zone Key` flag (bit 7 = 1) for subsequent zone record verification. Keys lacking the Zone Key flag are rejected from the trusted key set.
* **RFC 4034 §6.2 Canonical Wire Serialization & Case Normalization**: Guarantees that all domain names (both RR member owner names and RRSIG signer names) are converted to lowercase in the wire-format buffer prior to TBS digest calculation. Prevents digest verification failures on uppercase Base32hex NSEC3 owner names (common in `.com` and `.net` registries).
* **Full RRset Modeling in Negative Verification**: Negative proofs group all participating NSEC/NSEC3 records by owner and type into full RRsets before verifying RRSIGs, rather than validating isolated single-record fragments.
* **Authenticated Denial of DS Nonexistence (Anti-Downgrade)**: If a parent zone returns DS NODATA or NXDOMAIN, the resolver **does not** assume the child is unsigned. It cryptographically authenticates the parent's NSEC or NSEC3 denial-of-existence proof using the parent's DNSKEYs. Only an authenticated denial permits a transition to `InsecureUnsigned`; missing, forged, or unauthenticated DS denial proofs are declared `Bogus` → `SERVFAIL`. This defeats on-path DS-stripping downgrade attacks.
* **Global Cryptographic Work Budget (KeyTrap / CVE-2023-50387)**: Operates a thread-safe, unified `ValidationBudget` (`GLOBAL_MAX_SIG_CHECKS = 24`) shared globally across positive validations, negative proofs, DS verifications, and DNSKEY self-signatures, preventing CPU-exhaustion DoS from complex key/signature combinatorial attacks.
* **Centralized Signature Time Validation**: Enforces inception and expiration boundaries (`now >= inc && now <= exp`) centrally within `verify_rrsig()`. All validation callers (answer RRsets, NSEC/NSEC3 records, parent DS records, DNSKEY sets) uniformly enforce time boundaries, eliminating negative-proof replay and stale key vulnerabilities.
* **Rollover Availability & Signer Isolation**: In `validate_rrset()`, an expired or unauthorized signature does not cause an immediate `Bogus` failure. The validator evaluates all candidate signatures and only fails closed if zero authorized, time-valid signatures verify against a trusted anchor.
* **Algorithm Parity Enforcement**: Rejects signatures where the RRSIG algorithm does not strictly match the corresponding DNSKEY algorithm (`rrsig.algorithm() == dnskey.algorithm()`).
* **RFC 6672 DNAME Redirection Validation**: Supports `DNAME` (Type 39) validation. Cryptographically verifies the DNAME RRset and any accompanying synthesized CNAME RRset across multi-hop redirection chains with loop and depth limit enforcement.
* **Decomposed NSEC Proof Architecture (RFC 4035 §5.4)**: Decoupled into four distinct proof models:
  * **Direct NODATA**: Verifies matching owner, ensures `qtype` and `CNAME` bits are absent, and ensures `SOA` is absent for DS queries.
  * **Wildcard NODATA**: Confirms the wildcard `*.<closest>` exists, verifies requested types are absent from its bitmap, and proves the exact QNAME is covered.
  * **Direct NXDOMAIN**: Verifies QNAME nonexistence and proves the wildcard `*.<closest>` does not exist.
  * **Wildcard Expansion**: Proves no closer name exists that would have shadowed the wildcard.
* **Decomposed NSEC3 Proof Architecture (RFC 5155 §8)**:
  * **Closest Provable Encloser Walk**: Dedicated ancestor hashing walk (`find_nsec3_closest_provable_encloser`) distinct from standard NSEC walks.
  * **NSEC3 Parameter Consistency**: Enforces identical hash algorithms, iteration counts, and salts across all NSEC3 records participating in a proof.
  * **NSEC3 Opt-Out Handling (RFC 5155 §8.4)**: Evaluates the Opt-Out bit (`flags & 0x01 != 0`). Opt-Out NSEC3 records covering a next-closer name establish an insecure delegation (`InsecureUnsigned`) for DS queries, but are rejected if used to claim authenticated nonexistence (`Secure`) for records within a signed zone.
  * **Hash Length Enforcement**: Validates that decoded base32hex SHA-1 owner hashes are strictly 20 bytes.
* **RFC 9276 NSEC3 Iteration Cap**: NSEC3 records advertising more than 150 hash iterations are rejected as `InsecureUnknown` rather than hashed.
* **RFC 4035 §5.3.4 Wildcard Synthesis**: Accurately detects and synthesizes wildcard labels before canonical digest verification.
* **RFC 4034 §6.3 Canonical Sorting**: Reorders RRset members strictly by canonical RDATA octets prior to digest verification.
* **Authentic Data (AD) Flag**: Injects `AD=1` into responses when all records are cryptographically verified against the chain of trust.
* **Root Anchor Desync Fail-Open**: If the root anchor fails validation (e.g. an uncoordinated KSK rollover), the resolver fails open to Insecure rather than terminating resolution for the entire internet.

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
* **Subnet-Aware Token Bucket**: Aggregates traffic by `/24` IPv4 subnets and `/64` IPv6 prefixes to prevent attackers from rotating single IP addresses within a pool.
* **DNS ANY Drop**: Instantly drops UDP queries requesting type `ANY` to neutralize high-volume amplification vectors.
* **Adaptive Domain Throttling**:
  * 1st duplicate query in a one-second window: Allowed.
  * 2nd duplicate query: Challenged with `TC=1` (forces client to prove its source IP via TCP handshake).
  * 3rd+ duplicate query: Subject to a 3-second penalty drop.
* **Payload Amplification Challenges**: Forces TCP reconnection (`TC=1`) if an unauthenticated UDP response payload exceeds the client's advertised EDNS buffer.
* **Memory Protection**: Auto-prunes inactive rate-limiting buckets every 5 minutes and caps tracked domain buckets to 65,536 entries.

### Caching Engine
* **Stale-While-Revalidate**: Serves expired cached records immediately with zero client latency while asynchronously re-resolving and validating the domain in the background. A `Bogus` verdict during revalidation does **not** overwrite a previously-good cache entry, bounding the blast radius of transient upstream failures or poisoning attempts.
* **Exact TTL Preservation**: Upstream authoritative TTLs are preserved exactly up to a ceiling of 86,400 seconds without artificial floor clamping. Removed arbitrary 30s answer floors and 300s delegation floors, preventing extended exposure to stale records or delayed DNSKEY rollover windows.
* **Dynamic Zone-Signedness TTL**: Cached zone-signedness entries dynamically inherit the authoritative TTL from the validated DNSKEY set or negative DS denial proof, eliminating fixed 5-minute staleness windows when zones transition between signed and unsigned states.
* **Single-Flight Request Deduplication**: Uses an in-flight synchronization registry (`in_flight`) to ensure duplicate background revalidations are never triggered simultaneously for the same RRset.
* **EDNS `DO` Bit Partitioning**: Separate cache keys for `do=0` and `do=1` ensure clients requesting plain records do not receive bloated DNSSEC signatures, while validating clients retain RRSIGs.
* **Dynamic Transaction ID Rewriting**: Rewrites bytes 0 and 1 of cached wire responses on the fly to match the requesting client's query ID.
* **Delegation Caching**: Caches intermediate zone delegations (NS records and glue). Queries jump directly to the closest known ancestor rather than walking from the root on every lookup.
* **Negative & NODATA Caching**: Properly caches `NXDOMAIN` and empty `NOERROR` responses according to authority SOA TTL rules.
* **Atomic Disk Persistence**: Asynchronously syncs the in-memory cache to disk every 120 seconds and on clean shutdown using atomic file replacement (`.tmp` write followed by rename).
* **Tranco Cache Pre-warming**: Automatically downloads and unzips the Tranco Top 1M list on startup, warming the cache concurrently across A and AAAA records.

### Diagnostic & Inspection Engine (`dnscheck.rs`)
* **Real-Time Query Inspector**: Optional WebSocket watcher (`/watch/:client_id`) that streams incoming query metadata (remote IP, port, protocol, EDNS0 subnet, UDP buffer size) in real-time.
* **Deterministic Test Flags**: Supports testing flags encoded into query labels (`nullip`, `truncate`, `badsig`, `expiredsig`, `nosig`) for automated client validation and DNSSEC compliance testing.

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
| `RATE_LIMIT_BURST` | `300` | Maximum token bucket burst capacity per client subnet |
| `RATE_LIMIT_PER_SEC` | `60` | Sustained refill rate per second per client subnet |
| `CERT_PATH` | `fullchain.pem` | Path to TLS certificate chain |
| `KEY_PATH` | `privkey.pem` | Path to TLS private key |
| `WARM_LIMIT` | `0` | Number of top Tranco domains to pre-warm on launch (`0` to disable) |
| `WARM_CONCURRENCY` | `6` | Concurrency limit for background pre-warming |

---

## Building and Compiling

Ensure Rust (1.78 or newer) and Cargo are installed.

### 1. Compile Binary

```bash
cargo build --release
```

The compiled binary will be placed at `./target/release/doh-server`.

### 2. Granting Privileged Port Permissions (Recommended)

To run the binary as an unprivileged service user while still binding to low-numbered privileged ports (53, 443, 853):

```bash
sudo setcap 'cap_net_bind_service=+ep' ./target/release/doh-server
```

### Post-Quantum Signature Size Note

ML-DSA-44 signatures are 2,420 bytes and public keys are 1,312 bytes. A single Algorithm-18 RRSIG will exceed the 1,232-byte DNS Flag Day EDNS buffer on its own, so every post-quantum query automatically triggers a TCP fallback. This is expected and handled transparently by the recursor's truncation-detection path — no configuration is required — but clients should be aware that Algorithm-18 zones will always see a TCP retry, and TCP throughput should be sized accordingly.

---

## Deployment Architectures

### Option A: Standalone Deployment (Direct TLS)

In this configuration, the server directly manages all TLS operations for DoH and DoT using Let's Encrypt certificates.

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

Start the daemon:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now doh-server.service
```

---

### Option B: Reverse Proxy Deployment (Nginx + DoH Backend)

In this architecture, Nginx handles public HTTPS traffic (port 443) and proxies DoH requests to `127.0.0.1:3053` using `DOH_NO_TLS=1`. Plain DNS and DoT continue to run directly on ports 53 and 853.

#### 1. Systemd Service Configuration

```ini
[Unit]
Description=Unified Recursive DNS Server (Backend Mode)
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
Environment="DOH_PORT=3053"
Environment="DOH_NO_TLS=1"
Environment="DNSSEC_ENFORCE=1"
Environment="CERT_PATH=/etc/letsencrypt/live/dns.example.com/fullchain.pem"
Environment="KEY_PATH=/etc/letsencrypt/live/dns.example.com/privkey.pem"
Environment="RUST_LOG=info,doh_server=info"

Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

#### 2. Nginx Site Configuration

```nginx
upstream doh_backend {
    server 127.0.0.1:3053;
    keepalive 64;
}

server {
    listen 80;
    listen [::]:80;
    server_name dns.example.com;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name dns.example.com;

    ssl_certificate /etc/letsencrypt/live/dns.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dns.example.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_session_cache shared:DOH_SSL:20m;
    ssl_session_timeout 1d;

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

    # Health monitoring endpoint
    location = /health {
        proxy_pass http://doh_backend/health;
        proxy_set_header Host $host;
    }
}
```

---

## Verification & Testing

### 1. Plain DNS (UDP & TCP)

Test standard UDP resolution:

```bash
dig @127.0.0.1 -p 53 example.com A +dnssec
```

Test TCP fallback and functionality:

```bash
dig +tcp @127.0.0.1 -p 53 example.com A +dnssec
```

### 2. DNS-over-TLS (DoT)

Verify encrypted TLS DNS resolution using `kdig`:

```bash
kdig -d @dns.example.com:853 +tls example.com A
```

### 3. DNS-over-HTTPS (DoH)

Check system health and active cache size:

```bash
curl -s https://dns.example.com/health
```

Execute a wireformat query via HTTP POST:

```bash
# Base64-encoded query for example.com IN A
echo -n "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB" | base64 -d | \
  curl -s -X POST --data-binary @- \
  -H "Content-Type: application/dns-message" \
  -H "Accept: application/dns-message" \
  https://dns.example.com/dns-query | hexdump -C
```

Execute a query via HTTP GET (RFC 8484):

```bash
curl -s -H "Accept: application/dns-message" \
  "https://dns.example.com/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB" | hexdump -C
```

### 4. Comprehensive DNSSEC Validation Testing

The resolver achieves a **100% pass rate across all four algorithm suites and all four signature states** on [dnscheck.tools](https://dnscheck.tools/), validating classical curves, post-quantum signatures, and negative proof handling:

![DNSSEC Validation Test Results](images/Test.jpg)

* **ECDSA P-256 (alg13)**: Resolves successfully with `AD=1`.
* **ECDSA P-384 (alg14)**: Resolves successfully with `AD=1`.
* **Ed25519 (alg15)**: Resolves successfully with `AD=1`.
* **ML-DSA-44 (alg18)**: Post-quantum signatures resolve successfully with `AD=1`.
* **Invalid / Bad Signature (`badsig`)**: Resolution strictly blocked with `SERVFAIL` across all four algorithms.
* **Expired Signature (`expiredsig`)**: Expired time-bounds strictly blocked with `SERVFAIL` across all four algorithms.
* **Missing Signature (`nosig`)**: Unsigned records on signed zones strictly blocked with `SERVFAIL` across all four algorithms.

Quick verification of the ML-DSA-44 path:

```bash
# Positive: post-quantum zone signed exclusively with Algorithm 18 — expect AD=1
dig @127.0.0.1 -p 53 +dnssec test-alg18.dnscheck.tools A | grep -E "flags:|RRSIG"

# Negative: broken, expired, missing signatures — expect SERVFAIL for all three
for d in badsig expiredsig nosig; do
  echo -n "$d.test-alg18.dnscheck.tools: "
  dig @127.0.0.1 -p 53 +dnssec "$d.test-alg18.dnscheck.tools" A 2>/dev/null \
    | grep -oP '(?<=status: )\w+'
done
```

### 5. Negative-Answer (NSEC / NSEC3) & Authenticated Denial Validation

The resolver validates denial-of-existence proofs rather than trusting the mere presence of an NSEC/NSEC3 record:

```bash
# Signed zone, NXDOMAIN — expect AD=1 and validated NSEC/NSEC3 records
dig +dnssec @127.0.0.1 -p 53 nonexistent.cloudflare.com A

# Signed zone, NODATA — expect AD=1
dig +dnssec @127.0.0.1 -p 53 cloudflare.com AAAA

# Authenticated DS denial (genuinely insecure delegation) — expect AD=0, no SERVFAIL
dig +dnssec @127.0.0.1 -p 53 example.com A

# Deep NSEC3 hierarchy — expect AD=1 (exercises the closest-encloser walk)
dig +dnssec @127.0.0.1 -p 53 a.b.c.nonexistent.cloudflare.com A
```

To confirm the fix is load-bearing, strip the NSEC/NSEC3 records from a signed zone's negative response (e.g. with a local authoritative server or `scapy`) and re-query. The resolver will return `SERVFAIL` instead of caching an `AD=0` answer.

---

## Security Mitigations Matrix

| Threat Vector | Mitigation Strategy | RFC / CVE Reference |
| :--- | :--- | :--- |
| **DS-Stripping / Insecure Downgrade** | Rejection of empty DS responses unless accompanied by cryptographically verified parent NSEC/NSEC3 denial proofs | RFC 4035 §5.2, RFC 5155 §8.4, RFC 6840 §5.9 |
| **SSRF / Reflection via Glue** | Strict rejection of private, loopback, multicast, link-local, and cloud metadata IPs from glue and resolved NS addresses | RFC 1918, RFC 3927, RFC 6598 |
| **DNS Cache Poisoning & Record Injection** | Strict queried QNAME verification on answers, CNAME, and DNAME records; random TXID; randomized server selection | RFC 5452 |
| **Forged NXDOMAIN / Negative Poisoning** | Decomposed NSEC/NSEC3 state machines for NODATA, Wildcard NODATA, and NXDOMAIN; Opt-Out flag handling; 150-iteration cap | RFC 4035 §5.4, RFC 5155 §8, RFC 9276, CVE-2010-0097 |
| **Authoritative Upstream Misbehavior / Hangs** | Strict response classification (`FORMERR`/`NOTIMP` trigger server failover); unified whole-transaction TCP timeout (2500ms) | RFC 8906, BCP 145 |
| **KeyTrap Algorithmic Complexity** | Global `ValidationBudget` shared across all lookup stages (capped to 24 signature checks total) | CVE-2023-50387 |
| **DNAME Loop / Suffix Manipulation** | Bounded redirection chain tracking with cycle detection; cryptographic validation of both DNAME and synthesized CNAME RRsets | RFC 6672 |
| **DNSKEY Trust-Boundary Violation** | Strict enforcement of the `Zone Key` flag (bit 7 = 1) on authenticated keys; KSK authenticates full DNSKEY set per RFC 4035 §5.2 | RFC 4034 §2.1.1, RFC 4035 §5.2 |
| **Canonical TBS Wire Digest Mismatch** | Strict lowercase canonicalization of owner names and signer names in wire TBS construction (resolves Base32hex NSEC3 failures) | RFC 4034 §6.2 |
| **DNS Amplification** | Instant drop of UDP `ANY` queries; truncated challenges (`TC=1`) when response size exceeds EDNS payload | RFC 8482 |
| **Volumetric / DoS Floods** | Subnet-aggregated token bucket rate limiting (/24 IPv4, /64 IPv6) with progressive backoff | RFC 5358 |
| **NSEC3 Hash-Ring Forgery** | In-house NSEC3 hash-ring comparison and closest-encloser proof logic, avoiding an upstream advisory in `hickory-proto` 0.25.0..0.26.0-alpha.1 | GHSA-588m-chg6-8jqj |
| **DNS Wildcard Forgery** | Pre-verification label count calculation and wildcard synthesis; wildcard non-existence proven on every NSEC/NSEC3 negative response | RFC 4035 §5.3.4 |
| **Stale Key Window Over-Extension** | Elimination of minimum TTL clamping floors; zone-signedness cache inherits exact dynamic proof TTLs | RFC 4034, RFC 5011 |
| **Proxy Header Spoofing** | Proxy headers (`X-Real-IP`, `X-Forwarded-For`) only evaluated when incoming connection is from loopback | Security Best Practice |
| **Fragmented UDP Poisoning** | Outgoing EDNS buffer clamped to 1232 bytes to eliminate IP fragmentation; automatic TCP fallback for larger responses including all Algorithm-18 replies | DNS Flag Day 2020 |
| **Post-Quantum Signature Malleability** | ML-DSA-44 verification via RustCrypto `ml-dsa` ≥ 0.1.1, which rejects signatures with repeated hint indices (CVE-2026-24850) | CVE-2026-24850 |

---

## License

This project is licensed under the MIT License.
