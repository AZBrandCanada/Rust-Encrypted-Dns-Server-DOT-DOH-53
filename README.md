# What actually changed

Diagnosis, in order of impact:

1. **DoH was plaintext HTTP.** DoH (RFC 8484) requires HTTPS — any real
   client (browser, Android) just refuses to use a non-TLS endpoint.
   Fixed: DoH is now served over real TLS via `axum-server` on port 443.

2. **DoT self-signed a cert for `localhost`.** Android's Private DNS
   (hostname mode) checks the cert against a public CA for the exact
   hostname you type in Settings. A self-signed cert can never pass —
   Android just silently falls back to plaintext DNS, which is why it
   *looked* like DoT "wasn't working" rather than throwing an error.
   **This is not fixable in code.** You need a real certificate for a
   real domain name you control. See setup below — it's free and takes
   about 2 minutes with certbot.

3. **No delegation caching.** The old recursive resolver walked from
   the 13 root servers on every single query, with zero memory of
   "here's who handles `.com`" or "here's who handles `example.com`".
   Fixed: every delegation learned is cached by zone with its own TTL,
   and new queries start from the deepest cached zone instead of the
   root.

4. **No NODATA caching.** A NOERROR-with-zero-answers response (e.g. an
   AAAA query against an IPv4-only host — this happens on nearly every
   single web request, since most OSes query A and AAAA in parallel)
   was never cached, so it re-walked from the root every time. Fixed:
   NODATA is now cached the same as any other answer.

5. **Sequential nameserver queries.** One slow/dead nameserver added a
   full timeout of latency per hop. Fixed: up to 4 nameservers are
   raced in parallel per hop.

6. **Only IPv4 glue was read**, so referrals carrying only `AAAA` glue
   failed outright. Fixed: both are collected now.

7. **No loop guard beyond a step counter** — a misconfigured zone could
   burn the whole step budget doing nothing. Fixed: a referral that
   doesn't advance to a new zone aborts immediately.

8. **Cache pre-warming (10k domains, concurrency 32) fired at process
   start**, competing with live queries for sockets right when the
   server was least ready for it. Fixed: off by default, and when
   enabled, waits 60s after startup and defaults to concurrency 6.

None of this changes the fact that it's still a fully independent,
from-root recursive resolver — no Cloudflare, no upstream dependency.

---

# Setup

## 1. You need a domain name

There's no way around this for DoT/DoH to work with real clients. Point
an `A` (and `AAAA` if you have IPv6) record at your server's IP, e.g.
`dns.yourdomain.com -> your.server.ip`.

## 2. Get a real certificate (free, ~2 minutes)

The server doesn't use port 80 for anything, so certbot's standalone
mode is the simplest option:

```bash
sudo apt install certbot
sudo certbot certonly --standalone -d dns.yourdomain.com
```

That writes:
- `/etc/letsencrypt/live/dns.yourdomain.com/fullchain.pem`
- `/etc/letsencrypt/live/dns.yourdomain.com/privkey.pem`

Point the server at them:

```bash
export CERT_PATH=/etc/letsencrypt/live/dns.yourdomain.com/fullchain.pem
export KEY_PATH=/etc/letsencrypt/live/dns.yourdomain.com/privkey.pem
```

Certbot auto-renews via its systemd timer, but the running process
needs to reload the new cert — simplest is a renewal hook that restarts
the service:

```bash
sudo tee /etc/letsencrypt/renewal-hooks/deploy/restart-dns.sh <<'EOF'
#!/bin/sh
systemctl restart doh-server
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/restart-dns.sh
```

If you skip this step entirely, the server still starts — it just
generates a self-signed cert and logs a loud warning. That's fine for
poking at it locally with `curl -k` or `kdig`, but Android/browsers
will not use it.

## 3. Ports 53 / 443 / 853 need root, or a capability grant

Either run it as root, or grant the binary the capability instead:

```bash
sudo setcap 'cap_net_bind_service=+ep' /path/to/doh-server
```

## 4. Build and run

```bash
cargo build --release
./target/release/doh-server
```

Env vars (all optional):

| Var | Default | Meaning |
|---|---|---|
| `HOST` | `0.0.0.0` | Bind address |
| `DNS_PORT` | `53` | Plain UDP/TCP DNS |
| `DOT_PORT` | `853` | DNS-over-TLS |
| `DOH_PORT` | `443` | DNS-over-HTTPS |
| `CERT_PATH` / `KEY_PATH` | `fullchain.pem` / `privkey.pem` | TLS cert |
| `WARM_LIMIT` | `0` (off) | Pre-warm cache with top N domains on startup |
| `WARM_CONCURRENCY` | `6` | Parallelism for pre-warming |

## 5. Point clients at it

- **Android**: Settings → Network → Private DNS → Private DNS provider
  hostname → `dns.yourdomain.com`
- **DoH (Firefox, most browsers)**: `https://dns.yourdomain.com/dns-query`
- **Plain DNS**: just set it as your router/device's DNS server IP.

## Quick local test (before pointing real devices at it)

```bash
# plain DNS
dig @127.0.0.1 example.com

# DoT (expect a valid cert chain once you have a real one)
kdig -d @dns.yourdomain.com +tls example.com

# DoH
curl -k -H 'accept: application/dns-json' \
  'https://dns.yourdomain.com/dns-query?dns=<base64url-encoded-query>'
```

If `kdig`/`curl` fail with a certificate error, that's expected until
step 2 is done with a real domain — it confirms the self-signed
fallback is in fact the only thing standing between you and it working.
