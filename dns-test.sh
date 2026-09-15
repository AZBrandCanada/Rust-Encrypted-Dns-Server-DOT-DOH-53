#!/usr/bin/env bash
#
# AZBrand Recursive DNS Security / Edge-Case Test Suite
#
# Designed for Arch Linux using only common tools:
#   bash, dig, curl, openssl, python3
#
# Targets:
#   DNS UDP/TCP : 217.154.156.210:53
#   DoH         : https://doh-de.azbrand.ca/dns-query
#   DoT         : doh-de.azbrand.ca:853
#
# Usage:
#   chmod +x azbrand-dns-test.sh
#   ./azbrand-dns-test.sh
#
# Optional:
#   ./azbrand-dns-test.sh --skip-load
#   ./azbrand-dns-test.sh --skip-dot
#   ./azbrand-dns-test.sh --skip-doh
#   ./azbrand-dns-test.sh --skip-tcp
#
# IMPORTANT:
# - This script does NOT attempt destructive packet injection or cache poisoning
#   against the public Internet.
# - Tests requiring a deliberately malicious authoritative zone are reported as
#   MANUAL TESTS at the end. Those need a test domain/authoritative server you
#   control.
# - Load tests are deliberately conservative and opt-out with --skip-load.
#

set -u
set -o pipefail

SERVER="${SERVER:-217.154.156.210}"
DNS_PORT="${DNS_PORT:-53}"
DOH_URL="${DOH_URL:-https://doh-de.azbrand.ca/dns-query}"
DOT_HOST="${DOT_HOST:-doh-de.azbrand.ca}"
DOT_PORT="${DOT_PORT:-853}"

SKIP_LOAD=0
SKIP_DOT=0
SKIP_DOH=0
SKIP_TCP=0

for arg in "$@"; do
    case "$arg" in
        --skip-load) SKIP_LOAD=1 ;;
        --skip-dot)  SKIP_DOT=1 ;;
        --skip-doh)  SKIP_DOH=1 ;;
        --skip-tcp)  SKIP_TCP=1 ;;
        -h|--help)
            sed -n '1,52p' "$0"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            exit 2
            ;;
    esac
done

STAMP="$(date '+%Y%m%d-%H%M%S')"
OUTDIR="tests11/azbrand-dns-test-${STAMP}"
mkdir -p "$OUTDIR"

PASS=0
FAIL=0
WARN=0
INFO=0
MANUAL=0

SUMMARY="$OUTDIR/SUMMARY.txt"

say() {
    printf '%s\n' "$*" | tee -a "$SUMMARY"
}

pass() {
    PASS=$((PASS + 1))
    say "[PASS] $*"
}

fail() {
    FAIL=$((FAIL + 1))
    say "[FAIL] $*"
}

warn() {
    WARN=$((WARN + 1))
    say "[WARN] $*"
}

info() {
    INFO=$((INFO + 1))
    say "[INFO] $*"
}

manual() {
    MANUAL=$((MANUAL + 1))
    say "[MANUAL] $*"
}

section() {
    say ""
    say "================================================================"
    say "$*"
    say "================================================================"
}

have() {
    command -v "$1" >/dev/null 2>&1
}

status_from() {
    sed -n 's/.*status: \([A-Z0-9_]*\).*/\1/p' "$1" | head -1
}

flags_from() {
    sed -n 's/.*flags: \([^;]*\).*/\1/p' "$1" | head -1
}

answer_count_from() {
    sed -n 's/.*ANSWER: \([0-9]*\).*/\1/p' "$1" | head -1
}

time_from() {
    sed -n 's/.*Query time: \([0-9]*\) msec.*/\1/p' "$1" | head -1
}

run_dig() {
    local file="$1"
    shift
    dig "$@" >"$file" 2>&1
}

dns_test() {
    local label="$1"
    local name="$2"
    local type="$3"
    local expect="$4"
    local require_ad="${5:-0}"
    local transport="${6:-udp}"

    local file="$OUTDIR/${label}.txt"
    local args=()

    if [ "$transport" = "tcp" ]; then
        args+=(+tcp)
    fi

    run_dig "$file" "@${SERVER}" "$name" "$type" +dnssec +time=5 +tries=1 "${args[@]}" || true

    local status
    status="$(status_from "$file")"
    local flags
    flags="$(flags_from "$file")"
    local qtime
    qtime="$(time_from "$file")"

    say "[$label] $name $type [$transport] -> ${status:-UNKNOWN}, flags=${flags:-UNKNOWN}, ${qtime:-?}ms"

    if [ "$status" != "$expect" ]; then
        fail "$label expected $expect, got ${status:-UNKNOWN}"
        return 1
    fi

    if [ "$require_ad" = "1" ]; then
        if printf '%s' "$flags" | grep -qw ad; then
            pass "$label -> expected $expect + AD"
        else
            fail "$label -> expected AD flag"
            return 1
        fi
    else
        pass "$label -> $expect"
    fi

    return 0
}

# ------------------------------------------------------------
# Header / prerequisites
# ------------------------------------------------------------

section "AZBrand Recursive DNS Security / Edge-Case Test Suite"

say "Started : $(date)"
say "Server  : ${SERVER}:${DNS_PORT}"
say "DoH     : ${DOH_URL}"
say "DoT     : ${DOT_HOST}:${DOT_PORT}"
say "Output  : ${OUTDIR}"
say ""

for cmd in bash dig curl openssl python3; do
    if have "$cmd"; then
        pass "Required tool available: $cmd"
    else
        fail "Required tool missing: $cmd"
    fi
done

if [ "$FAIL" -ne 0 ]; then
    say ""
    say "Install the missing required tools and rerun."
    exit 2
fi

# ------------------------------------------------------------
# 1. Basic recursive resolution
# ------------------------------------------------------------

section "1. BASIC RECURSIVE RESOLUTION"

BASIC=(
    "example.com A"
    "example.com AAAA"
    "example.com MX"
    "example.com NS"
    "example.com SOA"
    "cloudflare.com A"
    "cloudflare.com AAAA"
    "google.com A"
    "google.com AAAA"
    "isc.org A"
    "com NS"
    ". NS"
)

i=0
for item in "${BASIC[@]}"; do
    read -r name type <<< "$item"
    i=$((i + 1))
    dns_test "basic-${i}" "$name" "$type" "NOERROR" 0 udp || true
done

# ------------------------------------------------------------
# 2. DNSSEC positive validation
# ------------------------------------------------------------

section "2. DNSSEC POSITIVE VALIDATION"

DNSSEC_POSITIVE=(
    "cloudflare.com A"
    "cloudflare.com AAAA"
    "cloudflare.com DNSKEY"
    "cloudflare.com DS"
    "cloudflare.com SOA"
    "google.com A"
    "google.com AAAA"
    "isc.org A"
    ". DNSKEY"
    ". SOA"
)

i=0
for item in "${DNSSEC_POSITIVE[@]}"; do
    read -r name type <<< "$item"
    i=$((i + 1))
    dns_test "dnssec-positive-${i}" "$name" "$type" "NOERROR" 1 udp || true
done

# ------------------------------------------------------------
# 3. DNSSEC failure detection
# ------------------------------------------------------------

section "3. DNSSEC FAILURE DETECTION"

dns_test "dnssec-failed" "dnssec-failed.org" "A" "SERVFAIL" 0 udp || true

# Query several times to ensure a cached bogus result remains bogus.
for i in 1 2 3; do
    dns_test "dnssec-failed-repeat-${i}" "dnssec-failed.org" "A" "SERVFAIL" 0 udp || true
done

# ------------------------------------------------------------
# 4. NXDOMAIN / NODATA
# ------------------------------------------------------------

section "4. NEGATIVE ANSWERS / NSEC / NSEC3"

NEGATIVE=(
    "does-not-exist-928374.cloudflare.com A"
    "does-not-exist-938475.cloudflare.com A"
    "does-not-exist-827364.isc.org A"
    "definitely-random-927364.example.com A"
    "cloudflare.com TXT"
    "cloudflare.com SRV"
    "cloudflare.com CAA"
)

i=0
for item in "${NEGATIVE[@]}"; do
    read -r name type <<< "$item"
    i=$((i + 1))
    file="$OUTDIR/negative-${i}.txt"
    run_dig "$file" "@${SERVER}" "$name" "$type" +dnssec +time=5 +tries=1 || true
    status="$(status_from "$file")"
    flags="$(flags_from "$file")"

    say "[$i] $name $type -> ${status:-UNKNOWN}, flags=${flags:-UNKNOWN}"

    if [ "$status" = "NXDOMAIN" ] || [ "$status" = "NOERROR" ]; then
        pass "Negative response accepted: $name $type -> $status"
    else
        fail "Unexpected negative response: $name $type -> ${status:-UNKNOWN}"
    fi
done

# ------------------------------------------------------------
# 5. DNSKEY / KSK / ZSK regression
# ------------------------------------------------------------

section "5. KSK / ZSK / DNSKEY RRSET AUTHENTICATION"

file="$OUTDIR/cloudflare-dnskey.txt"
run_dig "$file" "@${SERVER}" cloudflare.com DNSKEY +dnssec +time=5 +tries=1 || true

key_count="$(grep -Ec '^[^;[:space:]].+[[:space:]]DNSKEY[[:space:]]' "$file" || true)"
ksk_count="$(awk '$0 !~ /^;/ && $4 == "DNSKEY" && $5 == 257 {c++} END {print c+0}' "$file")"
zsk_count="$(awk '$0 !~ /^;/ && $4 == "DNSKEY" && $5 == 256 {c++} END {print c+0}' "$file")"

say "cloudflare.com DNSKEY records: $key_count"
say "KSK/SEP-style keys (flags 257): $ksk_count"
say "Zone keys with flags 256: $zsk_count"

if [ "$key_count" -ge 2 ]; then
    pass "Multiple DNSKEY records observed"
else
    warn "Could not confirm multiple DNSKEY records"
fi

if [ "$ksk_count" -ge 1 ] && [ "$zsk_count" -ge 1 ]; then
    pass "Both KSK-style and ZSK-style keys observed"
else
    warn "Could not confirm both 257 and 256 DNSKEY flags"
fi

# Repeated queries exercise DNSKEY and RRset caches.
for i in $(seq 1 10); do
    dns_test "ksk-zsk-cache-${i}" cloudflare.com A NOERROR 1 udp || true
done

# ------------------------------------------------------------
# 6. Cache / AD consistency
# ------------------------------------------------------------

section "6. CACHE / AD-BIT CONSISTENCY"

for i in $(seq 1 8); do
    file="$OUTDIR/cache-ad-${i}.txt"
    run_dig "$file" "@${SERVER}" cloudflare.com A +dnssec +time=5 +tries=1 || true
    status="$(status_from "$file")"
    flags="$(flags_from "$file")"

    if [ "$status" != "NOERROR" ]; then
        fail "Cache consistency iteration $i -> $status"
    elif printf '%s' "$flags" | grep -qw ad; then
        pass "Cache consistency iteration $i -> NOERROR + AD"
    else
        warn "Cache consistency iteration $i -> NOERROR but no AD"
    fi
done

# ------------------------------------------------------------
# 7. UDP vs TCP semantic comparison
# ------------------------------------------------------------

if [ "$SKIP_TCP" -eq 0 ]; then
    section "7. UDP VS TCP"

    COMPARE=(
        "cloudflare.com A"
        "cloudflare.com AAAA"
        "cloudflare.com DNSKEY"
        "google.com A"
        "isc.org A"
        ". DNSKEY"
    )

    i=0
    for item in "${COMPARE[@]}"; do
        read -r name type <<< "$item"
        i=$((i + 1))

        u="$OUTDIR/compare-${i}-udp.txt"
        t="$OUTDIR/compare-${i}-tcp.txt"

        run_dig "$u" "@${SERVER}" "$name" "$type" +dnssec +time=5 +tries=1 || true
        run_dig "$t" "@${SERVER}" "$name" "$type" +dnssec +tcp +time=5 +tries=1 || true

        us="$(status_from "$u")"
        ts="$(status_from "$t")"
        uf="$(flags_from "$u")"
        tf="$(flags_from "$t")"

        say "$name $type: UDP=$us [$uf], TCP=$ts [$tf]"

        if [ "$us" = "$ts" ]; then
            pass "UDP/TCP RCODE matches: $name $type"
        else
            fail "UDP/TCP RCODE differs: $name $type"
        fi
    done

    dns_test "tcp-cloudflare-A" cloudflare.com A NOERROR 1 tcp || true
    dns_test "tcp-cloudflare-DNSKEY" cloudflare.com DNSKEY NOERROR 1 tcp || true
    dns_test "tcp-root-DNSKEY" . DNSKEY NOERROR 1 tcp || true
fi

# ------------------------------------------------------------
# 8. EDNS behavior
# ------------------------------------------------------------

section "8. EDNS / DO BIT"

for size in 512 1232 1400 4096; do
    file="$OUTDIR/edns-${size}.txt"
    run_dig "$file" "@${SERVER}" cloudflare.com A +dnssec +bufsize="$size" +time=5 +tries=1 || true
    status="$(status_from "$file")"
    if [ "$status" = "NOERROR" ]; then
        pass "EDNS buffer $size -> NOERROR"
    else
        warn "EDNS buffer $size -> ${status:-UNKNOWN}"
    fi
done

file="$OUTDIR/edns-no-do.txt"
run_dig "$file" "@${SERVER}" cloudflare.com A +noedns +time=5 +tries=1 || true
status="$(status_from "$file")"
if [ "$status" = "NOERROR" ]; then
    pass "Query without EDNS -> NOERROR"
else
    warn "Query without EDNS -> ${status:-UNKNOWN}"
fi

# ------------------------------------------------------------
# 9. CNAME / redirect behavior
# ------------------------------------------------------------

section "9. CNAME / REDIRECTION"

CNAME_TESTS=(
    "www.github.com A"
    "www.microsoft.com A"
    "www.cloudflare.com A"
    "www.google.com A"
)

i=0
for item in "${CNAME_TESTS[@]}"; do
    read -r name type <<< "$item"
    i=$((i + 1))
    dns_test "cname-${i}" "$name" "$type" NOERROR 0 udp || true
done

info "CNAME loop / excessive-chain tests require a controlled authoritative test zone."

# ------------------------------------------------------------
# 10. DNAME discovery / behavior
# ------------------------------------------------------------

section "10. DNAME"

info "Searching public DNS for a DNAME owner is not reliable enough to turn into a pass/fail."
info "Use a controlled authoritative test zone for DNAME synthesis and DNSSEC validation."
manual "DNAME: create owner.example -> DNAME target.example and query child.owner.example."

# ------------------------------------------------------------
# 11. Wildcards
# ------------------------------------------------------------

section "11. WILDCARD / WILDCARD DENIAL"

info "Public wildcard behavior varies by zone and changes over time."
info "Query known wildcard test zones from your controlled test authority for definitive results."
manual "Wildcard expansion: existing wildcard -> Secure; non-matching name -> correct NSEC/NSEC3 denial."

# ------------------------------------------------------------
# 12. NSEC3 / Opt-Out
# ------------------------------------------------------------

section "12. NSEC3 / OPT-OUT"

info "NSEC3 and Opt-Out require carefully selected signed zones or a controlled authority."
manual "NSEC3 positive proof"
manual "NSEC3 NXDOMAIN"
manual "NSEC3 NODATA"
manual "NSEC3 Opt-Out insecure delegation"
manual "NSEC3 Opt-Out nonexistent child"
manual "NSEC3 wildcard denial"
manual "DS at an Opt-Out delegation"

# ------------------------------------------------------------
# 13. DS / DNSKEY chain
# ------------------------------------------------------------

section "13. DS / DNSKEY CHAIN"

CHAIN=(
    "cloudflare.com DS"
    "cloudflare.com DNSKEY"
    "com DNSKEY"
    ". DNSKEY"
)

i=0
for item in "${CHAIN[@]}"; do
    read -r name type <<< "$item"
    i=$((i + 1))
    dns_test "chain-${i}" "$name" "$type" NOERROR 1 udp || true
done

manual "DS mismatch: parent DS points to key A while child publishes key B -> expected SERVFAIL."
manual "Forged child DNSKEY RRset -> expected SERVFAIL."
manual "Missing DS with authenticated NSEC/NSEC3 denial -> expected Insecure, not Bogus."
manual "Unsigned delegation with invalid DS-denial proof -> expected SERVFAIL."

# ------------------------------------------------------------
# 14. RRSIG time validation
# ------------------------------------------------------------

section "14. RRSIG TIME VALIDATION"

manual "Expired RRSIG -> SERVFAIL."
manual "RRSIG inception in the future -> SERVFAIL."
manual "RRSIG just inside inception/expiration -> Secure."
manual "RRSIG exactly at expiration/inception boundary -> verify intended RFC semantics."

# ------------------------------------------------------------
# 15. RRSIG cryptographic integrity
# ------------------------------------------------------------

section "15. RRSIG CRYPTOGRAPHIC INTEGRITY"

manual "Modify one byte of signed RRset while keeping RRSIG -> SERVFAIL."
manual "Use wrong DNSKEY for valid-looking RRSIG -> SERVFAIL."
manual "RRSIG algorithm/key algorithm mismatch -> SERVFAIL."
manual "RRSIG signer name outside trusted zone -> SERVFAIL."
manual "Unauthorized/expired extra RRSIG alongside valid RRSIG -> valid RRset should remain Secure."

# ------------------------------------------------------------
# 16. Response structure / poisoning resistance
# ------------------------------------------------------------

section "16. RESPONSE STRUCTURE / POISONING RESISTANCE"

info "The resolver's response_matches() checks cannot be fully exercised with ordinary dig."
manual "Wrong TXID response must be discarded."
manual "Wrong QNAME response must be discarded."
manual "Wrong QTYPE response must be discarded."
manual "Wrong QCLASS response must be discarded."
manual "Wrong opcode response must be discarded."
manual "Multiple-question response must be discarded."
manual "Malformed/truncated DNS response must be discarded."

# ------------------------------------------------------------
# 17. Delegation / bailiwick / glue
# ------------------------------------------------------------

section "17. DELEGATION / BAILIWICK / GLUE"

manual "In-bailiwick glue A accepted."
manual "In-bailiwick glue AAAA accepted."
manual "Out-of-bailiwick glue ignored."
manual "Malicious additional A/AAAA outside bailiwick ignored."
manual "Nameserver address resolving to private IP rejected."
manual "Nameserver address changing between A/AAAA records handled safely."

# ------------------------------------------------------------
# 18. SSRF / private-address protection
# ------------------------------------------------------------

section "18. SSRF / PRIVATE ADDRESS PROTECTION"

manual "Controlled NS -> 127.0.0.1 must not be connected to."
manual "Controlled NS -> 10.0.0.1 must not be connected to."
manual "Controlled NS -> 172.16.0.1 must not be connected to."
manual "Controlled NS -> 192.168.0.1 must not be connected to."
manual "Controlled NS -> 169.254.169.254 must not be connected to."
manual "Controlled NS -> ::1 must not be connected to."
manual "Controlled NS -> fc00::/7 must not be connected to."
manual "Controlled NS -> fe80::/10 must not be connected to."

# ------------------------------------------------------------
# 19. IPv4 / IPv6 nameserver resolution
# ------------------------------------------------------------

section "19. NAMESERVER A / AAAA RESOLUTION"

file="$OUTDIR/ns-example.txt"
run_dig "$file" "@${SERVER}" cloudflare.com NS +dnssec +time=5 +tries=1 || true
if grep -q '^[^;].*[[:space:]]NS[[:space:]]' "$file"; then
    pass "Received authoritative NS records for cloudflare.com"
else
    warn "Could not parse cloudflare.com NS response"
fi

manual "Controlled delegation with only A glue."
manual "Controlled delegation with only AAAA glue."
manual "Controlled delegation with both A and AAAA glue."
manual "Glue absent: resolver must recursively resolve nameserver A/AAAA."

# ------------------------------------------------------------
# 20. TCP connection timeout / slow client
# ------------------------------------------------------------

section "20. TCP TIMEOUT / SLOW CLIENT"

if have nc; then
    info "nc is available; run only if you want the optional slow-client probe."
    manual "Open many incomplete TCP connections and verify bounded resource usage."
else
    info "nc not installed; slow TCP client test marked manual."
fi

# ------------------------------------------------------------
# 21. Cache behavior / TTL
# ------------------------------------------------------------

section "21. CACHE / TTL"

file="$OUTDIR/cache-ttl-1.txt"
file2="$OUTDIR/cache-ttl-2.txt"

run_dig "$file" "@${SERVER}" cloudflare.com A +dnssec +time=5 +tries=1 || true
sleep 2
run_dig "$file2" "@${SERVER}" cloudflare.com A +dnssec +time=5 +tries=1 || true

ttl1="$(awk '$4 == "A" && $1 == "cloudflare.com." {print $2; exit}' "$file")"
ttl2="$(awk '$4 == "A" && $1 == "cloudflare.com." {print $2; exit}' "$file2")"

if [ -n "${ttl1:-}" ] && [ -n "${ttl2:-}" ]; then
    say "cloudflare.com A TTL after first query: $ttl1"
    say "cloudflare.com A TTL after second query: $ttl2"
    if [ "$ttl2" -le "$ttl1" ]; then
        pass "TTL did not increase unexpectedly"
    else
        warn "TTL increased unexpectedly: $ttl1 -> $ttl2"
    fi
else
    warn "Could not parse TTLs for cache test"
fi

# ------------------------------------------------------------
# 22. DNSSEC cache regression
# ------------------------------------------------------------

section "22. DNSSEC CACHE REGRESSION"

for name in cloudflare.com google.com isc.org; do
    for i in 1 2 3 4 5; do
        file="$OUTDIR/cache-${name}-${i}.txt"
        run_dig "$file" "@${SERVER}" "$name" A +dnssec +time=5 +tries=1 || true
        status="$(status_from "$file")"
        flags="$(flags_from "$file")"

        if [ "$status" = "NOERROR" ] && printf '%s' "$flags" | grep -qw ad; then
            pass "Cached DNSSEC validation: $name iteration $i"
        elif [ "$status" = "NOERROR" ]; then
            warn "Cached DNSSEC answer lacks AD: $name iteration $i"
        else
            fail "Cached DNSSEC answer failed: $name iteration $i -> ${status:-UNKNOWN}"
        fi
    done
done

# ------------------------------------------------------------
# 23. Random-subdomain / cache growth test
# ------------------------------------------------------------

if [ "$SKIP_LOAD" -eq 0 ]; then
    section "23. CONSERVATIVE RANDOM-SUBDOMAIN LOAD"

    info "This sends 100 random queries. It is intentionally small for a public resolver."

    start="$(date +%s)"
    success=0
    failure=0

    for i in $(seq 1 100); do
        name="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(10) + ".example.com")
PY
)"
        file="$OUTDIR/random-${i}.txt"
        run_dig "$file" "@${SERVER}" "$name" A +dnssec +time=2 +tries=1 || true
        status="$(status_from "$file")"

        if [ "$status" = "NXDOMAIN" ] || [ "$status" = "NOERROR" ] || [ "$status" = "SERVFAIL" ]; then
            success=$((success + 1))
        else
            failure=$((failure + 1))
        fi
    done

    elapsed=$(( $(date +%s) - start ))
    say "Random query test: accepted responses=$success, unexpected=$failure, elapsed=${elapsed}s"

    if [ "$failure" -eq 0 ]; then
        pass "Random-subdomain test completed without malformed responses"
    else
        warn "Random-subdomain test had $failure unexpected responses"
    fi
else
    info "Random-subdomain load test skipped."
fi

# ------------------------------------------------------------
# 24. DoH
# ------------------------------------------------------------

if [ "$SKIP_DOH" -eq 0 ]; then
    section "24. DOH"

    # Basic TLS/HTTP endpoint check.
    file="$OUTDIR/doh-head.txt"
    curl -sS -I --max-time 10 "$DOH_URL" >"$file" 2>&1 || true

    if grep -q '^HTTP/' "$file"; then
        pass "DoH endpoint is reachable"
    else
        fail "DoH endpoint did not produce an HTTP response"
    fi

    # Generate RFC 8484 DNS wire queries using Python.
    python3 - "$DOH_URL" "$OUTDIR" <<'PY'
import base64
import os
import random
import struct
import subprocess
import sys
import urllib.request

url = sys.argv[1]
outdir = sys.argv[2]

def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode("ascii")
        out += bytes([len(b)]) + b
    return out + b"\x00"

def query(name, qtype, ident):
    qtypes = {
        "A": 1,
        "AAAA": 28,
        "DNSKEY": 48,
        "DS": 43,
    }
    flags = 0x0100
    header = struct.pack("!HHHHHH", ident, flags, 1, 0, 0, 0)
    question = encode_name(name) + struct.pack("!HH", qtypes[qtype], 1)
    return header + question

tests = [
    ("cloudflare.com", "A"),
    ("cloudflare.com", "AAAA"),
    ("cloudflare.com", "DNSKEY"),
    ("cloudflare.com", "DS"),
    ("google.com", "A"),
    ("isc.org", "A"),
    ("dnssec-failed.org", "A"),
    ("does-not-exist-938475.cloudflare.com", "A"),
]

for i, (name, qtype) in enumerate(tests, 1):
    ident = random.randrange(0, 65536)
    packet = query(name, qtype, ident)
    bodyfile = os.path.join(outdir, f"doh-query-{i}.bin")
    responsefile = os.path.join(outdir, f"doh-response-{i}.bin")

    open(bodyfile, "wb").write(packet)

    req = urllib.request.Request(
        url,
        data=packet,
        method="POST",
        headers={
            "Content-Type": "application/dns-message",
            "Accept": "application/dns-message",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            data = r.read()
            status = r.status
            ctype = r.headers.get("Content-Type", "")
        open(responsefile, "wb").write(data)

        if len(data) < 12:
            print(f"FAIL {name} {qtype}: HTTP {status}, response only {len(data)} bytes")
            continue

        rid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])

        ok_id = rid == ident
        qr = bool(flags & 0x8000)
        rcode = flags & 0x000f
        rcode_name = {
            0: "NOERROR",
            1: "FORMERR",
            2: "SERVFAIL",
            3: "NXDOMAIN",
            4: "NOTIMP",
            5: "REFUSED",
        }.get(rcode, str(rcode))

        if status != 200:
            print(f"FAIL {name} {qtype}: HTTP {status}")
        elif ctype.lower().split(";")[0].strip() != "application/dns-message":
            print(f"FAIL {name} {qtype}: wrong Content-Type {ctype!r}")
        elif not qr:
            print(f"FAIL {name} {qtype}: response QR bit not set")
        elif not ok_id:
            print(f"FAIL {name} {qtype}: transaction ID mismatch")
        elif name == "dnssec-failed.org" and rcode_name != "SERVFAIL":
            print(f"FAIL {name} {qtype}: expected SERVFAIL, got {rcode_name}")
        elif name.startswith("does-not-exist-") and rcode_name not in ("NXDOMAIN", "NOERROR"):
            print(f"FAIL {name} {qtype}: unexpected RCODE {rcode_name}")
        else:
            print(f"PASS {name} {qtype}: HTTP {status}, RCODE {rcode_name}, answers={an}, authority={ns}, additional={ar}")

    except Exception as e:
        print(f"FAIL {name} {qtype}: {e}")
PY

    doh_rc=0
    python3 - "$DOH_URL" "$OUTDIR" >/dev/null 2>&1 <<'PY'
# Existence check only; the full output is generated by the previous invocation.
raise SystemExit(0)
PY

    if grep -q '^PASS ' "$OUTDIR"/../does-not-exist 2>/dev/null; then
        :
    fi

    # Re-run the actual Python DoH test and capture its result.
    DOH_LOG="$OUTDIR/doh-results.txt"
    python3 - "$DOH_URL" "$OUTDIR" >"$DOH_LOG" 2>&1 <<'PY'
import random, struct, sys, urllib.request

url = sys.argv[1]

def enc(name):
    b=b""
    for x in name.rstrip(".").split("."):
        y=x.encode()
        b += bytes([len(y)])+y
    return b+b"\0"

types={"A":1,"AAAA":28,"DNSKEY":48,"DS":43}
tests=[
("cloudflare.com","A"),
("cloudflare.com","AAAA"),
("cloudflare.com","DNSKEY"),
("cloudflare.com","DS"),
("google.com","A"),
("isc.org","A"),
("dnssec-failed.org","A"),
("does-not-exist-938475.cloudflare.com","A"),
]

bad=0
for name, typ in tests:
    ident=random.randrange(65536)
    msg=struct.pack("!HHHHHH",ident,0x0100,1,0,0,0)+enc(name)+struct.pack("!HH",types[typ],1)
    req=urllib.request.Request(url,data=msg,method="POST",
        headers={"Content-Type":"application/dns-message","Accept":"application/dns-message"})
    try:
        with urllib.request.urlopen(req,timeout=15) as r:
            data=r.read(); code=r.status; ct=r.headers.get("Content-Type","")
        if len(data)<12:
            print(f"FAIL {name} {typ}: short response")
            bad+=1; continue
        rid,flags,qd,an,ns,ar=struct.unpack("!HHHHHH",data[:12])
        rcode=flags&15
        if rcode==0: rn="NOERROR"
        elif rcode==2: rn="SERVFAIL"
        elif rcode==3: rn="NXDOMAIN"
        else: rn=str(rcode)
        expected_bad=(name=="dnssec-failed.org")
        ok=(code==200 and ct.lower().split(";")[0].strip()=="application/dns-message"
            and (flags&0x8000) and rid==ident and
            ((not expected_bad) or rn=="SERVFAIL"))
        if ok:
            print(f"PASS {name} {typ}: HTTP={code} RCODE={rn} AN={an} NS={ns} AR={ar}")
        else:
            print(f"FAIL {name} {typ}: HTTP={code} CT={ct!r} RCODE={rn} ID={rid==ident} QR={bool(flags&0x8000)}")
            bad+=1
    except Exception as e:
        print(f"FAIL {name} {typ}: {e}")
        bad+=1
raise SystemExit(1 if bad else 0)
PY

    cat "$DOH_LOG" | tee -a "$SUMMARY"

    if grep -q '^FAIL ' "$DOH_LOG"; then
        fail "One or more DoH wire-format tests failed"
    else
        pass "DoH wire-format test suite completed without failures"
    fi
else
    info "DoH tests skipped."
fi

# ------------------------------------------------------------
# 25. DoT TLS
# ------------------------------------------------------------

if [ "$SKIP_DOT" -eq 0 ]; then
    section "25. DOT TLS"

    for proto in tls1_2 tls1_3; do
        file="$OUTDIR/dot-${proto}.txt"

        timeout 12 openssl s_client \
            -connect "${DOT_HOST}:${DOT_PORT}" \
            -servername "$DOT_HOST" \
            "-${proto}" \
            -verify_return_error \
            </dev/null >"$file" 2>&1 || true

        if grep -q 'Verify return code: 0 (ok)' "$file"; then
            pass "DoT $proto certificate verification succeeded"
        else
            fail "DoT $proto certificate verification failed"
        fi

        if grep -q 'Protocol.*TLSv1.3' "$file" || grep -q 'Protocol.*TLSv1.2' "$file"; then
            pass "DoT $proto negotiated TLS"
        else
            warn "Could not parse negotiated TLS protocol for $proto"
        fi
    done

    # Test that port 853 is actually reachable.
    if timeout 5 bash -c "</dev/tcp/${DOT_HOST}/${DOT_PORT}" 2>/dev/null; then
        pass "DoT TCP port 853 is reachable"
    else
        warn "Could not establish raw TCP connectivity to DoT port 853"
    fi
else
    info "DoT tests skipped."
fi

# ------------------------------------------------------------
# 26. DoT actual DNS-message query
# ------------------------------------------------------------

section "26. DOT DNS MESSAGE"

manual "DoT wire-format query: send DNS query over TLS and verify DNS response."
manual "DoT dnssec-failed.org must return SERVFAIL."
manual "DoT cloudflare.com A should return Secure/AD-equivalent validation state."
manual "DoT malformed DNS message must be rejected."

# ------------------------------------------------------------
# 27. DoH malformed input
# ------------------------------------------------------------

if [ "$SKIP_DOH" -eq 0 ]; then
    section "27. DOH MALFORMED INPUT"

    for payload in "" "x" "not-a-dns-message" "$(printf '\x00\x01\x02\x03')"; do
        code="$(
            if [ -z "$payload" ]; then
                curl -sS -o "$OUTDIR/doh-malformed-empty.bin" \
                    -w '%{http_code}' \
                    --max-time 10 \
                    -X POST \
                    -H 'Content-Type: application/dns-message' \
                    -H 'Accept: application/dns-message' \
                    --data-binary '' \
                    "$DOH_URL" 2>/dev/null
            else
                printf '%s' "$payload" | curl -sS \
                    -o "$OUTDIR/doh-malformed.bin" \
                    -w '%{http_code}' \
                    --max-time 10 \
                    -X POST \
                    -H 'Content-Type: application/dns-message' \
                    -H 'Accept: application/dns-message' \
                    --data-binary @- \
                    "$DOH_URL" 2>/dev/null
            fi
        )"

        if [ "$code" != "200" ]; then
            pass "Malformed DoH payload rejected with HTTP $code"
        else
            warn "Malformed DoH payload returned HTTP 200; inspect server behavior"
        fi
    done
fi

# ------------------------------------------------------------
# 28. HTTP method/content-type handling
# ------------------------------------------------------------

if [ "$SKIP_DOH" -eq 0 ]; then
    section "28. DOH HTTP METHOD / CONTENT-TYPE"

    for method in GET PUT DELETE PATCH; do
        code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 -X "$method" "$DOH_URL" 2>/dev/null || echo 000)"
        say "DoH $method -> HTTP $code"
        if [ "$method" = "GET" ]; then
            info "GET without dns= parameter is not a DNS query; response is informational."
        elif [ "$code" = "400" ] || [ "$code" = "405" ] || [ "$code" = "415" ]; then
            pass "DoH rejects unsupported $method with HTTP $code"
        else
            warn "DoH unsupported $method returned HTTP $code; review policy"
        fi
    done
fi

# ------------------------------------------------------------
# 29. Query-name / type / class edge cases
# ------------------------------------------------------------

section "29. QUERY EDGE CASES"

EDGE=(
    ". NS"
    ". SOA"
    "com NS"
    "com SOA"
    "cloudflare.com NS"
    "cloudflare.com TXT"
    "cloudflare.com CAA"
    "cloudflare.com MX"
    "cloudflare.com SRV"
)

i=0
for item in "${EDGE[@]}"; do
    read -r name type <<< "$item"
    i=$((i + 1))
    dns_test "edge-${i}" "$name" "$type" NOERROR 0 udp || true
done

# ------------------------------------------------------------
# 30. Unsupported / unusual query types
# ------------------------------------------------------------

section "30. UNUSUAL QUERY TYPES"

for type in ANY HTTPS SVCB TLSA PTR NAPTR CNAME; do
    file="$OUTDIR/type-${type}.txt"
    run_dig "$file" "@${SERVER}" cloudflare.com "$type" +dnssec +time=5 +tries=1 || true
    status="$(status_from "$file")"
    say "cloudflare.com $type -> ${status:-UNKNOWN}"

    case "$status" in
        NOERROR|NXDOMAIN|SERVFAIL|REFUSED)
            pass "Valid DNS response for type $type -> $status"
            ;;
        *)
            warn "Unexpected response for type $type -> ${status:-UNKNOWN}"
            ;;
    esac
done

# ------------------------------------------------------------
# 31. Case preservation / case-insensitive DNS names
# ------------------------------------------------------------

section "31. CASE / NAME CANONICALIZATION"

file="$OUTDIR/case.txt"
run_dig "$file" "@${SERVER}" ClOuDfLaRe.CoM A +dnssec +time=5 +tries=1 || true
status="$(status_from "$file")"

if [ "$status" = "NOERROR" ]; then
    pass "Mixed-case QNAME accepted"
else
    fail "Mixed-case QNAME failed: ${status:-UNKNOWN}"
fi

# ------------------------------------------------------------
# 32. Repeated-query stability
# ------------------------------------------------------------

section "32. REPEATED QUERY STABILITY"

for name in cloudflare.com google.com isc.org; do
    for i in $(seq 1 10); do
        file="$OUTDIR/stability-${name}-${i}.txt"
        run_dig "$file" "@${SERVER}" "$name" A +dnssec +time=5 +tries=1 || true
        status="$(status_from "$file")"

        if [ "$status" = "NOERROR" ]; then
            pass "Stability: $name iteration $i"
        else
            fail "Stability: $name iteration $i -> ${status:-UNKNOWN}"
        fi
    done
done

# ------------------------------------------------------------
# 33. Conservative concurrent load
# ------------------------------------------------------------

if [ "$SKIP_LOAD" -eq 0 ]; then
    section "33. CONSERVATIVE CONCURRENT LOAD"

    info "50 concurrent queries; intentionally conservative for a public resolver."

    pids=()
    for i in $(seq 1 50); do
        (
            dig "@${SERVER}" "load-${i}-$(date +%s).example.com" A +time=3 +tries=1 \
                >"$OUTDIR/load-${i}.txt" 2>&1
        ) &
        pids+=("$!")
    done

    bad=0
    for pid in "${pids[@]}"; do
        wait "$pid" || bad=$((bad + 1))
    done

    if [ "$bad" -eq 0 ]; then
        pass "50 concurrent queries completed without process failures"
    else
        warn "$bad concurrent query processes returned non-zero"
    fi
else
    info "Concurrent load test skipped."
fi

# ------------------------------------------------------------
# 34. Manual adversarial tests
# ------------------------------------------------------------

section "34. MANUAL ADVERSARIAL TESTS REQUIRED FOR FULL COVERAGE"

manual "1. Controlled bad RRSIG: alter one signed RRset byte -> SERVFAIL."
manual "2. Controlled expired RRSIG -> SERVFAIL."
manual "3. Controlled future-inception RRSIG -> SERVFAIL."
manual "4. Controlled DS mismatch -> SERVFAIL."
manual "5. Controlled forged DNSKEY RRset -> SERVFAIL."
manual "6. Controlled unsigned delegation with valid authenticated DS absence -> NOERROR/Insecure."
manual "7. Controlled invalid DS-absence proof -> SERVFAIL."
manual "8. Controlled NSEC3 NXDOMAIN proof."
manual "9. Controlled NSEC3 NODATA proof."
manual "10. Controlled NSEC3 Opt-Out insecure delegation."
manual "11. Controlled NSEC3 Opt-Out signed child."
manual "12. Controlled wildcard Secure answer."
manual "13. Controlled wildcard denial proof."
manual "14. Controlled CNAME loop."
manual "15. Controlled CNAME chain exceeding recursion limit."
manual "16. Controlled DNAME synthesis."
manual "17. Controlled DNAME loop/pathological redirection."
manual "18. Controlled out-of-bailiwick glue poisoning."
manual "19. Controlled NS A -> 127.0.0.1 SSRF attempt."
manual "20. Controlled NS A -> 169.254.169.254 SSRF attempt."
manual "21. Controlled NS AAAA -> ::1 SSRF attempt."
manual "22. Controlled NS AAAA -> fc00::/7 SSRF attempt."
manual "23. Wrong TXID injection."
manual "24. Wrong QNAME response injection."
manual "25. Wrong QTYPE response injection."
manual "26. Multiple-question response injection."
manual "27. Malformed UDP response."
manual "28. Malformed TCP response."
manual "29. Slow/incomplete TCP client flood."
manual "30. DoT malformed DNS-message test."
manual "31. DoT dnssec-failed.org -> SERVFAIL."
manual "32. DoH GET with valid dns= wire-format parameter."
manual "33. DoH POST with valid application/dns-message."
manual "34. DoH oversized request."
manual "35. DoH malformed DNS packet."
manual "36. DNSKEY rollover with old+new KSK/ZSK."
manual "37. DNSKEY revoked-key behavior."
manual "38. RRSIG algorithm mismatch."
manual "39. Unauthorized expired RRSIG alongside valid signature."
manual "40. Signature-budget exhaustion using a controlled DNSSEC response."

# ------------------------------------------------------------
# Final report
# ------------------------------------------------------------

section "FINAL RESULT"

say "PASS   : $PASS"
say "FAIL   : $FAIL"
say "WARN   : $WARN"
say "INFO   : $INFO"
say "MANUAL : $MANUAL"
say ""
say "Full test artifacts are in:"
say "  $OUTDIR/"
say ""
say "Summary:"
say "  $SUMMARY"
say ""

if [ "$FAIL" -gt 0 ]; then
    say "RESULT: FAILURES DETECTED"
    say "Do not treat the resolver as fully validated until the failures are investigated."
    exit 1
elif [ "$WARN" -gt 0 ]; then
    say "RESULT: NO HARD FAILURES, BUT WARNINGS REQUIRE REVIEW"
    exit 0
else
    say "RESULT: AUTOMATED TESTS PASSED"
    say "Manual adversarial tests are still required for complete DNSSEC/recursive-resolver assurance."
    exit 0
fi
