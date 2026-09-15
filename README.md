# Unified Recursive DNS Server

A high-performance, lightweight, multi-protocol **iterative recursive DNS resolver written in Rust**.

The server provides standard DNS over **UDP/TCP**, **DNS-over-TLS (DoT)**, and **DNS-over-HTTPS (DoH)** while resolving domains directly through the DNS hierarchy—from the root servers to authoritative nameservers—without forwarding queries to third-party recursive resolvers such as Google Public DNS, Cloudflare, or Quad9.

The resolver combines a client-independent canonical cache with full DNSSEC validation, authenticated positive and negative responses, DNSKEY/DS trust chains, NSEC/NSEC3 denial proofs, CNAME/DNAME processing, RFC 1982 DNSSEC time arithmetic, ML-DSA-44 DNSSEC verification, stale-answer handling, rate limiting, anti-amplification defenses, and SSRF-resistant iterative resolution.

---

## Architecture

All inbound transports share a single resolution pipeline. Transport-specific protocol handling occurs at the edge; recursive resolution, DNSSEC validation, caching, and client response construction are centralized.

A key architectural property is the strict separation between **canonical resolver state** and **client-specific wire representation**.

The cache stores validated DNS data and its explicit DNSSEC security state. It does **not** store client-specific flags such as transaction IDs, RD/CD/AD state, or DO-dependent wire representations.

```text
       UDP :53 ─────┐
       TCP :53 ─────┤
      DoT :853 ─────┤
      DoH :443 ─────┤
      DoH :3053 ────┘
                     │
                     ▼
          Inbound Transport & Framing
          ───────────────────────────
          • DNS UDP/TCP
          • RFC 7766 TCP framing
          • RFC 7858 DoT
          • RFC 8484 DoH
          • 65,535-byte UDP receive buffer
                     │
                     ▼
          Request Parsing & Controls
          ──────────────────────────
          • Single-question enforcement
          • Subnet token bucket
          • UDP duplicate-domain RRL
          • ANY query handling
                     │
                     ▼
       Iterative Recursive Resolution
       ──────────────────────────────
       • Root → TLD → authoritative
       • Bailiwick validation
       • Safe glue handling
       • CNAME/DNAME traversal
       • IPv4-prioritized NS racing
                     │
                     ▼
             DNSSEC Validation
             ─────────────────
             • DS/DNSKEY chains
             • RRSIG validation
             • NSEC/NSEC3 proofs
             • Positive/negative validation
             • ML-DSA-44
                     │
              ┌──────┴──────┐
              ▼             ▼
      Canonical DNS Data  DnssecStatus
                          • Secure
                          • InsecureUnsigned
                          • InsecureUnknown
                          • Bogus
              └──────┬──────┘
                     ▼
                CacheEntry
          {qname}:{qtype}:IN
                     │
                     ▼
             Cache Freshness
          ┌──────────┼──────────┐
          ▼          ▼          ▼
        Fresh       Stale     Expired
          │          │          │
          │          │          └─► Synchronous resolution
          │          │
          │          └────────────► Background revalidation
          │
          └───────────────────────┐
                                  ▼
                  Client Response Construction
                  ─────────────────────────────
                  1. Age client-visible TTLs
                  2. Preserve RRSIG Original TTL
                  3. Retrieve stored DnssecStatus
                  4. Calculate AD according to DNSSEC state
                  5. Filter DNSSEC records when appropriate
                  6. Apply transaction ID and client flags
                  7. Construct client EDNS/OPT response
                  8. Enforce response-size policy
                                  │
                                  ▼
                         Final DNS Response
```

### Canonical Cache Model

Each cache entry contains:

* Canonical validated DNS response data
* Effective cache TTL
* Cache timestamps
* Explicit `DnssecStatus`

Client-specific properties are generated only when serving the response.

This avoids maintaining separate DO=0 and DO=1 caches and prevents one client's DNS flags from leaking into another client's response.

---

# Features

## Multi-Protocol Transport

### Concurrent DNS, DoT, and DoH

The server concurrently supports:

* Plain DNS over UDP
* Plain DNS over TCP
* DNS-over-TLS on port 853
* DNS-over-HTTPS on port 443
* Reverse-proxy DoH backend mode

All transports eventually enter the same recursive resolution and validation engine.

### RFC 8484 DoH

The DoH implementation supports both standard RFC 8484 request forms:

* `GET` with a base64url-encoded `dns` parameter
* `POST` with an `application/dns-message` body

HTTP request validation distinguishes protocol errors from DNS resolution errors:

* Missing `dns` parameter → `400 Bad Request`
* Empty `dns` parameter → `400 Bad Request`
* Malformed DNS wire message → `400 Bad Request`
* Missing/invalid POST `Content-Type` → `415 Unsupported Media Type`
* Incompatible `Accept` header → `406 Not Acceptable`
* Rate-limited request → `429 Too Many Requests`
* Valid DNS query producing `SERVFAIL` → `200 OK` with DNS wire response

### DNS TCP and DoT Framing

TCP and DoT use standard two-byte DNS message length framing.

The maximum DNS message payload is **65,535 bytes**, the largest value representable by the DNS two-byte length field.

The server supports:

* Persistent connections
* Multiple queries per connection
* TCP pipelining
* TLS connections with ALPN `dot`
* 10-second idle timeout
* 5-second active I/O timeout
* Clean handling of EOF and socket failures

### UDP Receive Handling

The application receive buffer is sized to **65,535 bytes**, preventing application-level truncation of otherwise valid UDP datagrams.

The resolver separately enforces an operational **4,096-byte maximum inbound UDP query size**, rejecting unusually large requests before recursive processing.

### Reverse-Proxy Mode

DoH can operate without local TLS using:

```text
DOH_NO_TLS=1
```

This allows Nginx, Caddy, or another reverse proxy to terminate HTTPS while forwarding HTTP/1.1 traffic to the resolver.

### Development Certificates

When configured TLS certificate files are unavailable, the server can generate a self-signed development certificate automatically.

On Unix systems, generated private keys are protected with restrictive `0600` permissions.

### Unprivileged Port Fallback

When privileged ports cannot be bound, the server automatically falls back to:

| Service | Privileged | Fallback |
| ------- | ---------: | -------: |
| DNS     |         53 |     5053 |
| DoT     |        853 |     8853 |
| DoH     |        443 |     8443 |

### Bounded Concurrency

Tokio semaphores limit concurrent work to reduce resource exhaustion:

* UDP: 2,048 permits
* TCP: 512 permits
* DoT: 512 permits

---

# Iterative Recursive Resolution

## Direct Root-to-Authoritative Resolution

The resolver does not forward requests to public recursive DNS services.

Resolution begins at the IANA root server system:

```text
Root
  │
  ▼
TLD
  │
  ▼
Authoritative nameservers
  │
  ▼
Final RRset
```

The resolver independently follows referrals until the requested data or authenticated denial proof is obtained.

## Dual-Stack Nameserver Racing

Authoritative nameserver addresses are collected from both IPv4 and IPv6 records.

Candidates are:

1. Validated against the resolver's safe-address policy
2. Ordered with IPv4 prioritized
3. Queried concurrently in batches of three

IPv4 prioritization reduces failures on systems without functional IPv6 routing while retaining IPv6 support.

## CNAME Chain Traversal

When an authoritative response contains multiple CNAME hops, the resolver follows the chain directly within the response whenever possible.

This avoids unnecessary network requests when the authoritative server has already supplied subsequent links in the chain.

## DNAME Synthesis

The resolver implements RFC 6672 DNAME processing.

When a DNAME redirects a queried name, the resolver:

1. Performs canonical suffix substitution
2. Synthesizes the required CNAME when necessary
3. Preserves the DNAME's TTL
4. Validates the resulting chain
5. Returns `YXDOMAIN` when the synthesized name exceeds the DNS maximum name length

## DNSSEC Material Preservation

When CNAME or DNAME responses are merged across resolution stages, the resolver preserves the DNSSEC material required to validate each step, including relevant:

* RRSIG
* NSEC
* NSEC3
* DNSKEY

records.

This prevents response-merging logic from accidentally discarding cryptographic evidence needed by the validator.

## Strict Authoritative Acceptance

Authoritative responses are not accepted merely because they contain an `AA` flag.

Empty authoritative responses must contain meaningful terminal information such as an SOA or valid delegation state. Otherwise, the resolver rejects the response as making no authoritative progress.

## Referral and Bailiwick Validation

Delegation responses are checked for coherent NS information and safe glue.

Glue addresses are accepted directly only when they satisfy the resolver's bailiwick requirements.

Out-of-bailiwick nameserver addresses are resolved independently rather than trusted as arbitrary address hints.

This mitigates cache poisoning attacks involving forged or out-of-bailiwick glue.

## Upstream Response Failover

Authoritative nameservers are treated independently.

Transient or unusable responses such as:

* `SERVFAIL`
* `REFUSED`
* `FORMERR`
* `NOTIMP`

can cause the resolver to fail over to other nameserver candidates rather than immediately abandoning the resolution.

## EDNS Compatibility Fallback

The resolver requests EDNS0 with a 1,232-byte payload size.

When an authoritative server demonstrates broken EDNS behavior—for example through malformed OPT handling or an EDNS-related `FORMERR`—the resolver can retry using plain RFC 1035 DNS.

## TCP Fallback

Responses with `TC=1` are retried over TCP.

TCP connection, write, length-read, and payload-read operations are collectively bounded by a whole-transaction timeout to prevent stalled authoritative servers from consuming resources indefinitely.

## Upstream DNSSEC Queries

Iterative upstream queries are issued with:

```text
RD=0
CD=1
```

The resolver performs DNSSEC validation itself rather than requesting upstream recursive validation.

Setting `CD=1` prevents an upstream validating resolver from interfering with the resolver's own validation decisions.

## Recursion Bounds

The resolver limits recursive work through multiple independent bounds:

* Maximum recursion depth: `16`
* Maximum resolution steps: `16`
* Maximum CNAME/DNAME redirection hops: `16`

Cycle detection prevents repeated traversal of the same resolution state.

## Parent-Zone DS Resolution

DS records are queried from the **parent zone**, not from the child zone.

This follows the DNSSEC delegation model and prevents a child from being treated as authoritative for its own delegation proof.

---

# DNSSEC Validation

The resolver implements DNSSEC validation from the root trust anchor downward.

```text
Root Trust Anchor
       │
       ▼
Root DNSKEY
       │
       ▼
Parent DS
       │
       ▼
Child DNSKEY
       │
       ▼
Child RRSIG
       │
       ▼
Authenticated RRset
```

Validation covers both positive and negative DNS responses.

## Root Trust Anchors

The resolver includes the current root trust anchors:

* Root KSK-2017, Key Tag `20326`
* Root KSK-2024, Key Tag `38696`

Root and intermediate authentication failures are treated as validation failures.

With:

```text
DNSSEC_ENFORCE=1
```

broken DNSSEC validation results in `SERVFAIL`.

With:

```text
DNSSEC_ENFORCE=0
```

validation failures do not produce an authenticated (`AD=1`) response.

> Root trust anchors are embedded in the resolver and must be updated when the IANA DNSSEC root trust-anchor set changes.

## DNSSEC Security States

Every validated cache entry records an explicit security state:

```text
Secure
InsecureUnsigned
InsecureUnknown
Bogus
```

This state is preserved independently from the response wire representation.

## DNSKEY and DS Trust Chains

The validator walks the trust chain from the root toward the target zone.

For each signed delegation it:

1. Resolves the parent DS
2. Validates the DS RRset
3. Resolves the child DNSKEY RRset
4. Matches the DS against the child DNSKEY
5. Validates the DNSKEY RRset
6. Uses authenticated zone keys to validate subsequent RRsets

Authenticated child DNSKEY cache lifetime is bounded by:

```text
min(child DNSKEY TTL, parent DS TTL)
```

This prevents an authenticated DNSKEY from remaining trusted longer than the delegation information that authenticated it.

## KSK/ZSK Trust Model

The validator distinguishes between:

* Keys used to authenticate the DNSKEY RRset
* Zone keys used to authenticate ordinary zone data

The DNSKEY `Zone Key` flag is enforced when selecting keys for ordinary RRset validation.

## RRSIG Time Validation

DNSSEC signature inception and expiration timestamps are treated as 32-bit DNS serial numbers.

RFC 1982 serial-number arithmetic is used instead of naive integer comparison, including across the DNSSEC timestamp rollover boundary.

## Canonical DNSSEC Serialization

DNSSEC verification uses canonical DNS wire serialization.

Owner names and signer names are normalized appropriately before constructing signed data, and RRset members are sorted according to canonical RDATA ordering before digest verification.

## Authenticated Negative Responses

Negative responses are validated cryptographically rather than trusting `NXDOMAIN` or empty answers by themselves.

The validator supports:

* NODATA
* NXDOMAIN
* Wildcard NODATA
* Wildcard NXDOMAIN
* Authenticated DS nonexistence

### Authenticated SOA

For authoritative negative responses, the SOA RRset is validated against the zone's DNSKEYs before the negative response can be considered `Secure`.

### NSEC

NSEC validation verifies the appropriate denial relationships, including:

* Exact-name existence
* Type bitmap absence
* Wildcard conditions
* NXDOMAIN coverage

### NSEC3

NSEC3 validation implements the closest-provable-encloser model and validates:

* NSEC3 hash ordering
* Closest encloser
* Next-closer coverage
* Wildcard denial
* NODATA conditions
* NXDOMAIN conditions

### NSEC3 Opt-Out

Opt-Out records are treated conservatively.

An Opt-Out proof can establish an insecure delegation for an appropriate **DS query**, but it is not accepted as generic proof that arbitrary records do not exist inside a signed zone.

### NSEC3 Iteration Limits

NSEC3 records exceeding the configured safe iteration threshold are rejected rather than processed indefinitely.

The implementation follows the operational guidance of RFC 9276 and rejects NSEC3 records advertising more than 150 iterations.

## DS Nonexistence Downgrade Protection

An empty DS response is not automatically interpreted as proof that a delegation is insecure.

The resolver requires authenticated parent-zone denial evidence before treating DS nonexistence as an insecure delegation.

This prevents unauthenticated DS omission from being interpreted as a legitimate downgrade from DNSSEC validation.

---

# Post-Quantum DNSSEC

The resolver supports **ML-DSA-44 / DNSSEC Algorithm 18** in addition to conventional DNSSEC algorithms.

ML-DSA-44 verification is implemented through the RustCrypto `ml-dsa` backend rather than relying exclusively on protocol-library support.

The implementation follows:

* NIST FIPS 204
* DNSSEC Algorithm 18 specifications

ML-DSA-44 signatures and public keys are substantially larger than conventional DNSSEC signatures, so Algorithm 18 responses frequently exceed the 1,232-byte EDNS payload target.

The resolver automatically falls back to TCP when an authoritative server truncates such responses.

---

# Cryptographic Verification Backends

The DNSSEC engine uses multiple verification backends.

### Classical Cryptography

The optimized `ring` backend handles supported:

* RSA/SHA-256
* RSA/SHA-512
* ECDSA P-256/SHA-256
* ECDSA P-384/SHA-384
* Ed25519

RSA keys are bounded to the supported 2,048–8,192-bit range.

### Post-Quantum Cryptography

The RustCrypto `ml-dsa` backend handles:

* ML-DSA-44
* DNSSEC Algorithm 18

### Native Protocol Fallback

Remaining supported DNSSEC algorithms are delegated to the native `hickory-proto` verification implementation where appropriate.

---

# Cryptographic Resource Limits

DNSSEC validation is subject to a per-query cryptographic work budget.

```text
PER_VALIDATION_MAX_SIG_CHECKS = 24
```

The same validation budget is carried across the validation process rather than independently resetting for each stage.

The budget applies across:

* Positive RRset validation
* Negative proof validation
* DS validation
* DNSKEY validation
* DNSKEY self-signatures
* Other signature verification stages

This limits algorithmic CPU consumption from deliberately complex DNSSEC responses and mitigates KeyTrap-style denial-of-service attacks.

---

# Caching Engine

The cache is designed around canonical DNS state rather than client-specific DNS responses.

Cache keys are:

```text
{qname}:{qtype}:IN
```

Each cache entry contains:

```text
Canonical DNS response
Effective TTL
Cache timestamps
DnssecStatus
```

There is no separate DO=0/DO=1 cache.

## DNSSEC-Aware Effective TTL

For `Secure` data, the effective cache lifetime is bounded by the remaining validity of the RRSIGs required to authenticate the cached data.

Conceptually:

```text
effective_ttl =
    min(normal_min_ttl,
        remaining_required_rrsig_validity)
```

RRSIG expiration is calculated using RFC 1982 serial arithmetic.

This ensures authenticated data cannot remain `Fresh` beyond the validity of the signatures authenticating it.

## Dynamic TTL Aging

Cached DNS record TTLs are aged when responses are served:

```text
remaining_ttl = max(effective_ttl - age, 0)
```

The cryptographic `Original TTL` contained inside RRSIG RDATA is never modified.

EDNS OPT records are excluded from ordinary DNS TTL aging.

## Cache Freshness

Each cache entry has one of three runtime freshness states.

### Fresh

```text
age < effective TTL
```

The response is served immediately with dynamically aged record TTLs.

### Stale

```text
effective TTL <= age < effective TTL + MAX_STALE_SECS
```

The response can be served under RFC 8767 stale-answer handling.

Stale responses receive a positive **30-second wire TTL** and trigger asynchronous background revalidation.

Stale DNSSEC responses always clear:

```text
AD=0
```

### Expired

```text
age >= effective TTL + MAX_STALE_SECS
```

The cached response is no longer served.

The resolver performs synchronous recursive resolution instead.

If resolution fails, the resolver returns `SERVFAIL` rather than resurrecting an expired response.

## Client-Specific Response Construction

The canonical cache is converted into a client-specific DNS response only at request time.

The response builder:

1. Ages client-visible TTLs
2. Retrieves the stored DNSSEC security state
3. Determines whether `AD` can be set
4. Applies the client's DO/CD/AD signaling
5. Filters DNSSEC records when appropriate
6. Injects the client transaction ID
7. Echoes appropriate request flags
8. Constructs the client EDNS response
9. Applies response-size policy

For a `Secure` response, `AD=1` requires:

* Validated `DnssecStatus::Secure`
* Fresh cache data
* Appropriate client DNSSEC signaling
* `CD=0`

Stale responses never receive `AD=1`.

## Persistent Cache Hygiene

Cache entries are persisted periodically and on clean shutdown.

Persistence uses an atomic temporary-file write followed by rename.

At startup:

* Entries missing explicit `dnssec_status` are discarded
* Expired entries are discarded
* Entries outside the allowable stale window are discarded
* Valid entries are restored without assuming an unverified DNSSEC state

This deliberately avoids silently assigning a security state to legacy cache data.

## Single-Flight Revalidation

An in-flight registry prevents multiple concurrent background revalidations from independently refreshing the same cache entry.

## Tranco Pre-Warming

Optional startup pre-warming can populate the cache using the Tranco Top 1M list.

Pre-warmed responses pass through normal recursive resolution and DNSSEC validation.

Secure responses use the same DNSSEC-aware effective TTL calculation as ordinary cache entries.

---

# Resolver Hardening

## SSRF Protection

Nameserver addresses obtained through delegation and glue are validated before being used for outbound connections.

The resolver rejects unsafe address ranges including:

### IPv4

* Private networks
* Loopback
* Link-local
* Carrier-grade NAT
* Benchmark/testing ranges
* Multicast
* Unspecified
* Other prohibited special-use ranges

### IPv6

* Loopback
* Link-local
* Unique Local Addresses
* Multicast
* Unspecified
* IPv4-mapped unsafe addresses

Cloud metadata addresses such as `169.254.169.254` are therefore not accepted as recursive upstream targets.

This prevents malicious DNS delegation data from turning the recursive resolver into an SSRF primitive.

## Reverse-Proxy Header Protection

Headers such as:

```text
CF-Connecting-IP
X-Real-IP
X-Forwarded-For
```

are trusted only when the immediate connection originates from loopback.

Remote clients cannot simply inject proxy headers to impersonate another source address.

---

# Rate Limiting and Abuse Protection

## Subnet Token Bucket

Traffic is aggregated by:

* IPv4 `/24`
* IPv6 `/64`

Token acquisition uses atomic compare-and-update operations to avoid negative token balances under concurrent load.

## Transport Isolation

Connection-oriented transports—TCP, DoT, and DoH—use the subnet token bucket without UDP duplicate-domain penalties.

This avoids incorrectly penalizing legitimate pipelined DNS connections.

## UDP Duplicate-Domain RRL

UDP duplicate queries are tracked per domain and time epoch.

The policy is:

```text
1st duplicate → allowed
2nd duplicate → TC=1 challenge
3rd+ duplicate → temporary drop
```

The per-second epoch and counter are updated atomically.

This provides an inexpensive response-rate control mechanism without introducing global locks.

## RRL Memory Bound

The duplicate-domain tracking table is capped at:

```text
65,536 entries
```

When capacity is reached, new domains fall back to normal token-bucket processing rather than causing global UDP traffic to be dropped.

## ANY Queries

UDP `ANY` queries are dropped immediately to reduce their usefulness as amplification vectors.

---

# Environment Variables

| Variable             |         Default | Description                                                    |
| -------------------- | --------------: | -------------------------------------------------------------- |
| `HOST`               |       `0.0.0.0` | Bind address for listeners                                     |
| `DNS_PORT`           |            `53` | Plain DNS port; falls back to `5053` when necessary            |
| `DOT_PORT`           |           `853` | DNS-over-TLS port; falls back to `8853`                        |
| `DOH_PORT`           |           `443` | DNS-over-HTTPS port; falls back to `8443`                      |
| `DOH_NO_TLS`         |             `0` | Set to `1` when TLS is terminated by a reverse proxy           |
| `DNSSEC_ENFORCE`     |             `1` | Return `SERVFAIL` when DNSSEC validation fails                 |
| `MAX_STALE_SECS`     |           `300` | Maximum stale-serving window                                   |
| `RATE_LIMIT_BURST`   |           `300` | Token-bucket burst capacity per client subnet                  |
| `RATE_LIMIT_PER_SEC` |            `60` | Token-bucket refill rate per second                            |
| `CERT_PATH`          | `fullchain.pem` | TLS certificate chain                                          |
| `KEY_PATH`           |   `privkey.pem` | TLS private key                                                |
| `WARM_LIMIT`         |             `0` | Number of Tranco domains to pre-warm; `0` disables pre-warming |
| `WARM_CONCURRENCY`   |             `6` | Maximum concurrent pre-warming operations                      |

---

# Building

The project requires Rust and Cargo.

```bash
cargo build --release
```

The resulting executable is:

```text
./target/release/doh-server
```

For privileged ports, either run with the appropriate capability or use the configured high-port fallbacks.

For example:

```bash
sudo setcap 'cap_net_bind_service=+ep' ./target/release/doh-server
```

---

# Post-Quantum DNS Response Size

ML-DSA-44 signatures are significantly larger than conventional DNSSEC signatures:

```text
ML-DSA-44 signature: 2,420 bytes
ML-DSA-44 public key: 1,312 bytes
```

Consequently, DNS responses containing Algorithm 18 signatures can exceed the 1,232-byte EDNS payload target recommended for avoiding IP fragmentation.

The resolver handles `TC=1` responses by retrying the query over TCP.

---

# Deployment

## Option A, Standalone Deployment

The resolver can terminate DoT and DoH TLS directly.

Example systemd service:

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

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now doh-server.service
```

---

## Option B, Reverse Proxy Deployment

A reverse proxy can terminate public HTTPS while the resolver listens locally in HTTP mode.

Example architecture:

```text
Internet
   │
   ▼
Nginx :443
   │
   │ HTTP/1.1
   ▼
127.0.0.1:3053
   │
   ▼
Unified DNS Resolver
```

Configure:

```text
DOH_NO_TLS=1
DOH_PORT=3053
```

Example Nginx configuration:

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

    location = /dns-query {
        proxy_pass http://doh_backend/dns-query;

        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;

        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        proxy_buffering off;
        proxy_request_buffering off;
    }

    location = /health {
        proxy_pass http://doh_backend/health;
        proxy_set_header Host $host;
    }
}
```

The resolver's proxy-header protection ensures forwarded client identity is only trusted when the immediate connection is from a trusted local proxy.

---

# Verification

## Plain DNS

```bash
dig @127.0.0.1 -p 53 example.com A +dnssec
```

TCP:

```bash
dig +tcp @127.0.0.1 -p 53 example.com A +dnssec
```

## DNS-over-TLS

```bash
kdig -d @dns.example.com:853 +tls example.com A
```

## DNS-over-HTTPS

### POST

```bash
echo -n "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB" \
  | base64 -d \
  | curl -s -X POST \
      --data-binary @- \
      -H "Content-Type: application/dns-message" \
      -H "Accept: application/dns-message" \
      https://dns.example.com/dns-query \
  | hexdump -C
```

### GET

```bash
curl -s \
  -H "Accept: application/dns-message" \
  "https://dns.example.com/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB" \
  | hexdump -C
```

## DNSSEC Failure Test

```bash
dig @127.0.0.1 -p 53 dnssec-failed.org A
```

Expected result:

```text
SERVFAIL
```

## Valid DNSSEC Test

```bash
dig @127.0.0.1 -p 53 cloudflare.com A +dnssec
```

Expected result:

```text
NOERROR
flags: ... ad ...
```

---

# Security Model

| Threat                               | Mitigation                                                                                      |
| ------------------------------------ | ----------------------------------------------------------------------------------------------- |
| Broken root trust chain              | Strict DNSSEC validation and fail-closed enforcement                                            |
| DS stripping / downgrade             | Authenticated DS nonexistence proofs required                                                   |
| Parent DS rollover desynchronization | Child DNSKEY trust lifetime bounded by parent DS TTL                                            |
| DNSSEC signature expiration          | Effective cache TTL bounded by required RRSIG validity                                          |
| Forged negative responses            | Cryptographically validated NSEC/NSEC3 proofs                                                   |
| NSEC3 Opt-Out abuse                  | Opt-Out accepted only for appropriate insecure delegations                                      |
| DNS cache poisoning                  | Transaction ID validation, response matching, bailiwick controls, randomized upstream selection |
| Forged/out-of-bailiwick glue         | Bailiwick validation and independent resolution                                                 |
| Recursive SSRF                       | Special-use/private/link-local/metadata address filtering                                       |
| Broken EDNS servers                  | EDNS fallback to plain DNS                                                                      |
| Slow authoritative servers           | Whole-transaction TCP timeouts and bounded recursion                                            |
| CNAME/DNAME loops                    | Hop limits and cycle detection                                                                  |
| DNAME name overflow                  | RFC 6672 name-length validation                                                                 |
| DNSSEC algorithmic DoS               | Per-validation signature budget                                                                 |
| DNS amplification                    | ANY handling, response-size enforcement, UDP duplicate-domain RRL                               |
| Volumetric flooding                  | Subnet token-bucket rate limiting                                                               |
| UDP duplicate flooding               | Atomic per-domain RRL                                                                           |
| Stale DNSSEC authentication          | Stale responses always clear `AD`                                                               |
| Zombie cache entries                 | Hard expiration after stale window                                                              |
| Legacy cache downgrade               | Entries without explicit DNSSEC state are discarded                                             |
| Proxy identity spoofing              | Forwarded headers trusted only from loopback                                                    |
| UDP application truncation           | 65,535-byte receive buffer                                                                      |
| Post-quantum response truncation     | Automatic TCP retry after `TC=1`                                                                |

---

# Design Principles

The resolver is built around several core principles:

### 1. Resolve, don't forward

The server performs iterative resolution itself instead of outsourcing recursion to a public resolver.

### 2. Validate before trusting

Delegations, glue, DNSSEC signatures, negative proofs, and cached security state are independently validated before being trusted.

### 3. Keep canonical state separate from presentation

The cache represents resolver state, not one particular client's DNS request.

### 4. Never manufacture security state

Legacy or incomplete cache entries are discarded rather than assigned an assumed DNSSEC status.

### 5. Expiration is security-sensitive

DNSSEC signature validity constrains cache lifetime. Expired authenticated data cannot remain `Fresh`.

### 6. Stale data is explicitly unauthenticated

RFC 8767 stale responses are served with `AD=0`, regardless of their previous DNSSEC state.

### 7. Bound every expensive operation

Recursive depth, resolution steps, redirections, concurrent connections, rate limits, and cryptographic verification are all explicitly bounded.

### 8. Treat network-provided addresses as untrusted input

Delegation glue and resolved nameserver addresses are filtered before they can become outbound connection targets.

---

# License

This project is licensed under the **MIT License**.
