# DNS Server

A high-performance, lightweight, multi-protocol recursive DNS server built in Rust. It serves plain DNS (UDP/TCP), DNS-over-TLS (DoT), and DNS-over-HTTPS (DoH) simultaneously while performing independent, from-root recursive resolution without relying on upstream resolvers like Cloudflare or Google.

---

## Features & Architecture

* **Multi-Protocol Support**: Handles UDP/TCP DNS (port 53), DoT (port 853), and DoH (port 443 / 3053) concurrently in a single binary.
* **From-Root Recursive Resolver**: Performs full root-zone iterations independently with no external upstream dependencies.
* **Smart Delegation & Zone Caching**: Learns zone delegations with their respective TTLs and starts subsequent queries from the deepest known cached zone rather than restarting from root servers.
* **NODATA & NXDOMAIN Caching**: Caches empty `NOERROR` responses (such as `AAAA` lookups on IPv4-only domains) and non-existent domains to prevent unnecessary query loops.
* **Parallel Nameserver Racing**: Races up to 4 nameservers concurrently per hop to eliminate latency spikes caused by slow or unresponsive nameservers.
* **Dual IPv4/IPv6 Glue Processing**: Collects both `A` and `AAAA` glue records during referrals.
* **Loop Guard Protection**: Immediately aborts query walks if a referral fails to advance to a deeper zone.
* **Configurable Cache Pre-Warming**: Optional background cache warming for top domains, deferred by 60 seconds at boot with controlled concurrency to prevent socket exhaustion.

---

## Prerequisites

1. **Domain Name**: A public domain or subdomain (e.g., `dns.example.com`) pointing to your server's IP address. Real clients (Android Private DNS, iOS, Browsers) strictly require valid TLS certificates matching the FQDN.
2. **TLS Certificate**: A valid certificate from Let's Encrypt or ZeroSSL.
3. **Capabilities / Root Permissions**: Binding to low ports (53, 443, 853) requires `root` execution or capability grants via `setcap`.

---

## Build & Installation

### 1. Compile the Binary

```bash
cargo build --release
```

The compiled binary will be located at `./target/release/doh-server`.

### 2. Grant Network Binding Capabilities (Optional)

If running the daemon under an unprivileged system user:

```bash
sudo setcap 'cap_net_bind_service=+ep' ./target/release/doh-server
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `HOST` | `0.0.0.0` | IP address to bind network listeners |
| `DNS_PORT` | `53` | Plain UDP/TCP DNS port |
| `DOT_PORT` | `853` | DNS-over-TLS (DoT) port |
| `DOH_PORT` | `443` (or `3053` behind proxy) | DNS-over-HTTPS (DoH) port |
| `CERT_PATH` | `fullchain.pem` | Path to TLS certificate (`.crt` or `.pem`) |
| `KEY_PATH` | `privkey.pem` | Path to TLS private key (`.key`) |
| `CACHE_FILE` | None | File path for persistent disk cache storage |
| `WARM_LIMIT` | `0` (off) | Pre-warm cache with top N domains on boot |
| `WARM_CONCURRENCY` | `6` | Max concurrent worker threads for pre-warming |

---

## Deployment Setup

### 1. Systemd Service

Create `/etc/systemd/system/doh-server.service`:

```ini
[Unit]
Description=Unified DNS Server (DoH + Port 53 UDP/TCP)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/ryan/dns
Environment=PORT=3053
Environment=DOH_PORT=3053
Environment=DOT_PORT=853
Environment=DNS_PORT=53
Environment=HOST=0.0.0.0
Environment=CACHE_FILE=/home/ryan/dns/cache.json
Environment=CERT_PATH=/etc/ssl/certs/dns.example.com.crt
Environment=KEY_PATH=/etc/ssl/private/dns.example.com.key
ExecStart=/home/ryan/dns/target/release/doh-server
Restart=always
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now doh-server.service
```

---

### 2. Nginx Reverse Proxy (Port 443 DoH Termination)

When proxying DoH through Nginx, Nginx handles HTTPS on port 443 and passes queries to `doh-server` running on port `3053`.

> **Note**: Because `doh-server` serves TLS directly on its configured backend port, `proxy_pass` must use `https://` with `proxy_ssl_verify off;`.

Create `/etc/nginx/sites-available/dns.example.com`:

```nginx
upstream doh_backend {
    server 127.0.0.1:3053;
    keepalive 64;
}

# HTTP Server (Port 80)
server {
    listen 80;
    listen [::]:80;
    server_name dns.example.com;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
        default_type "text/plain";
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

# HTTPS Server (Port 443)
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name dns.example.com;

    ssl_certificate /etc/ssl/certs/dns.example.com.crt;
    ssl_certificate_key /etc/ssl/private/dns.example.com.key;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
        default_type "text/plain";
    }

    ssl_session_cache shared:DOH_SSL:20m;
    ssl_session_timeout 1d;
    ssl_session_tickets on;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    keepalive_timeout 120s;
    keepalive_requests 10000;

    client_max_body_size 10k;

    location / {
        proxy_pass https://doh_backend;
        proxy_ssl_verify off;
        proxy_http_version 1.1;

        proxy_set_header Connection "";
        proxy_set_header Host $host;

        proxy_set_header CF-Connecting-IP $http_cf_connecting_ip;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_request_buffering off;
        proxy_buffering off;

        proxy_connect_timeout 3s;
        proxy_send_timeout 5s;
        proxy_read_timeout 5s;
    }
}
```

Enable the vhost configuration:

```bash
sudo ln -s /etc/nginx/sites-available/dns.example.com /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

---

## Client Configuration

* **Android (Private DNS / DoT)**:
  `Settings` → `Network & Internet` → `Private DNS` → `Private DNS provider hostname` → `dns.example.com`
* **Web Browsers (DoH)**:
  `Settings` → `Privacy & Security` → `Secure DNS` → Custom Provider URL: `https://dns.example.com/dns-query`
* **Plain DNS**:
  Set your router or network device's primary DNS address to your server's IPv4/IPv6 address.

---

## Verification & Testing

### 1. Plain DNS Test (UDP/TCP Port 53)
```bash
dig @dns.example.com example.com
```

### 2. DoT Test (TCP Port 853)
```bash
kdig -d @dns.example.com +tls example.com
```

### 3. DoH Native Test (HTTPS Port 443)
```bash
dig +https @dns.example.com example.com
```

### 4. Direct RFC 8484 DoH Curl Test
```bash
curl -i -H 'accept: application/dns-message' \
  '[https://dns.example.com/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAEC](https://dns.example.com/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAEC)'
```