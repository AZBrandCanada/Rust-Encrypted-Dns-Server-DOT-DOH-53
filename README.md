mkdir -p .

cat << 'EOF' | sed 's/^:::/```/' > README.md
<!-- README.md -->
# DNS Server

A high-performance, lightweight, multi-protocol recursive DNS server built in Rust. It serves plain DNS (UDP/TCP), DNS-over-TLS (DoT), and DNS-over-HTTPS (DoH) simultaneously while performing independent, from-root recursive resolution without relying on upstream third-party resolvers.

---

## Features & Architecture

### Protocols & Transport
* **Multi-Protocol Concurrency**: Handles plain UDP/TCP DNS (port 53), DNS-over-TLS (port 853), and DNS-over-HTTPS (port 443 / 3053) concurrently in a single binary.
* **Reverse Proxy Compatibility**: Supports optional plain HTTP backend mode (`DOH_NO_TLS=1`) when running behind Nginx, eliminating double-TLS encryption overhead.
* **Unprivileged Local Fallback**: Automatically falls back to high ports (`5053`, `8853`, `8443`) when run locally without root permissions.

### DNSSEC Validation & Protection
* **Full Chain Cryptographic Validation**: Validates signature chains from root trust anchors down to authoritative zones using `ring`. Supports ECDSA P-256, ECDSA P-384, Ed25519, and RSA (2048-8192 bits).
* **RFC 4035 §5.3.4 Wildcard Synthesis**: Accurately validates wildcard-expanded records by synthesizing the canonical wildcard label before verification.
* **RFC 4034 §6.3 Canonical Ordering**: Normalizes RRset order strictly by canonical RDATA octets.
* **Authentic Data (AD) Flag**: Sets `AD=1` on cryptographically proven records.
* **Active Tamper Blocking**: Returns `SERVFAIL` on expired, forged, or missing signatures on signed zones (100% pass rate on `dnscheck.tools`).

### Anti-Cache Poisoning & Resolver Hardening
* **0x20 Case Randomization**: Randomizes letter casing in question names (e.g. `eXaMpLe.CoM`) on outgoing recursor queries. Off-path spoofing attacks must guess the exact case pattern in addition to transaction IDs and UDP source ports.
* **Strict Response Validation**: Verifies Transaction ID, question name, query type, and query class before trusting answers.
* **In-Bailiwick Glue Enforcement**: Drops out-of-bailiwick glue records from referral Additional sections to prevent parent-zone poisoning attacks.
* **Parallel Nameserver Racing**: Concurrently queries up to 4 nameservers per hop and takes the fastest valid response, eliminating latency spikes from dead nameservers.

### Abuse Defense & Rate Limiting
* **Per-IP Token Bucket**: Caps query burst size and sustained query rate per client IP to mitigate amplification and DoS attacks.
* **Proxy-Aware Tracking**: Extracts real client IPs from `X-Real-IP` and `X-Forwarded-For` HTTP headers behind Nginx.
* **Loopback Exemption**: Exempts `127.0.0.1` and `::1` from throttling to protect internal monitoring and health checks.
* **Automatic Bucket Pruning**: Background worker purges stale client buckets every 5 minutes to prevent memory leaks from randomized spoofed source IPs.

### Caching Engine
* **Delegation Caching**: Stores zone delegations (NS + glue) with respective TTLs; subsequent queries start at the deepest cached ancestor rather than re-walking the root servers.
* **Negative & NODATA Caching**: Caches `NXDOMAIN` and empty `NOERROR` responses (e.g. `AAAA` lookups on IPv4-only hosts) to avoid root re-query loops.
* **Stale-While-Revalidate**: Serves expired cached records immediately while refreshing them asynchronously in the background.
* **Disk Persistence**: Syncs memory cache to disk every 120 seconds and gracefully upon shutdown.

---

## Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `HOST` | `0.0.0.0` | IP address to bind listeners |
| `DNS_PORT` | `53` | Plain UDP/TCP DNS port (fallback: `5053`) |
| `DOT_PORT` | `853` | DNS-over-TLS port (fallback: `8853`) |
| `DOH_PORT` | `443` | DNS-over-HTTPS port (fallback: `8443`, or `3053` behind Nginx) |
| `DOH_NO_TLS` | `0` | Set to `1` for plain HTTP backend mode when Nginx terminates TLS |
| `DNSSEC_ENFORCE` | `0` | Set to `1` to strictly return SERVFAIL on broken public DNSSEC chains |
| `RATE_LIMIT_BURST` | `300` | Maximum queries a single client IP can burst |
| `RATE_LIMIT_PER_SEC` | `60` | Sustained queries per second allowed per IP |
| `CERT_PATH` | `fullchain.pem` | Path to TLS certificate |
| `KEY_PATH` | `privkey.pem` | Path to TLS private key |
| `WARM_LIMIT` | `0` | Number of top Tranco domains to pre-warm on boot (`0` = disabled) |
| `WARM_CONCURRENCY` | `6` | Maximum worker concurrency for cache pre-warming |

---

## Build & Installation

### 1. Compile

:::bash
cargo build --release
:::

The compiled binary will be located at `./target/release/doh-server`.

### 2. Network Capabilities (Optional)

If running the daemon under an unprivileged user while binding to privileged ports (53, 853, 443):

:::bash
sudo setcap 'cap_net_bind_service=+ep' ./target/release/doh-server
:::

---

## Deployment Configuration

### 1. Systemd Service

Create `/etc/systemd/system/doh-server.service`:

:::ini
[Unit]
Description=Unified Recursive DNS Server (DoH / DoT / Plain DNS)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/azbrand/dns
ExecStart=/home/azbrand/dns/target/release/doh-server

Environment="HOST=0.0.0.0"
Environment="DNS_PORT=53"
Environment="DOT_PORT=853"
Environment="DOH_PORT=3053"
Environment="DOH_NO_TLS=1"
Environment="RATE_LIMIT_BURST=300"
Environment="RATE_LIMIT_PER_SEC=60"
Environment="CERT_PATH=/etc/letsencrypt/live/dns.example.com/fullchain.pem"
Environment="KEY_PATH=/etc/letsencrypt/live/dns.example.com/privkey.pem"
Environment="RUST_LOG=info,doh_server=info"

Restart=always
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
:::

Enable and start the service:

:::bash
sudo systemctl daemon-reload
sudo systemctl enable --now doh-server.service
:::

---

### 2. Nginx Reverse Proxy (Port 443 DoH Termination)

When proxying DoH through Nginx with `DOH_NO_TLS=1`, Nginx terminates public HTTPS on port 443 and passes plain HTTP queries to `127.0.0.1:3053`:

:::nginx
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

    location /dns-query {
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

    location /health {
        proxy_pass http://doh_backend/health;
        proxy_set_header Host $host;
    }
}
:::

---

## Verification & Testing

### 1. Plain DNS (UDP/TCP)
:::bash
dig @127.0.0.1 -p 53 example.com A
dig +tcp @127.0.0.1 -p 53 example.com A
:::

### 2. DNS-over-TLS (DoT)
:::bash
kdig -d @dns.example.com +tls example.com
:::

### 3. DNS-over-HTTPS (DoH)
:::bash
# Health endpoint
curl -s https://dns.example.com/health

# RFC 8484 GET query
curl -s -H "Accept: application/dns-message" \
  "https://dns.example.com/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
:::

### 4. DNSSEC Verification
Run an end-to-end verification through `dnscheck.tools`:
* Open `https://dnscheck.tools/` in a browser configured to use your DoH or DoT endpoint.
* All checks for **Valid**, **Invalid**, **Expired**, and **Missing** signatures will report **PASS (green)** across ECDSA P-256, P-384, and Ed25519.
EOF