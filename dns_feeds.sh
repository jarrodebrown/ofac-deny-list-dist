#!/bin/bash
#
# dns_feeds.sh — build a dnsmasq-style DNS sinkhole blocklist from public
# malware / C2 DOMAIN feeds, in hosts format ("0.0.0.0 domain").
#
# Scope is deliberately MALWARE/C2 ONLY — not ad/tracker blocking — so it will
# not sinkhole legitimate sites and break normal browsing on the home LAN.
#
# A feed being unreachable is tolerated (its fetch just yields nothing). Output
# is one "0.0.0.0 <domain>" line per unique domain, written to $1.
#
set -u
OUT="${1:-dns_blocklist.hosts}"
tmp="$(mktemp)"
raw="$(mktemp)"
fetch(){ curl -fsSL --retry 2 --connect-timeout 15 --max-time 60 "$1" 2>/dev/null || true; }

{
  # abuse.ch URLhaus — active malware distribution hostnames (hosts format).
  fetch "https://urlhaus.abuse.ch/downloads/hostfile/"
  # malware-filter's cleaned URLhaus domain set (hosts format, de-noised).
  fetch "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt"
  # abuse.ch ThreatFox aggressive domain IOCs (hosts format).
  fetch "https://threatfox.abuse.ch/downloads/hostfile/"
} > "$raw" 2>/dev/null

# Normalize: strip comments, take the domain field from hosts-format lines
# (0.0.0.0 / 127.0.0.1 <domain>), keep bare-domain lines too, lowercase,
# drop localhost + obviously-invalid + wildcard-root entries.
grep -vE '^[[:space:]]*#' "$raw" \
  | tr 'A-Z' 'a-z' \
  | awk '{ if ($1=="0.0.0.0"||$1=="127.0.0.1") print $2; else if (NF==1) print $1 }' \
  | grep -E '^[a-z0-9._-]+\.[a-z]{2,}$' \
  | grep -vE '^(localhost|localhost\.localdomain|local|broadcasthost|ip6-)' \
  | sort -u > "$tmp"

n=$(wc -l < "$tmp" | tr -d ' ')
echo "dns feeds: ${n} unique malware/C2 domains" >&2

# Emit hosts format sinkholing to 0.0.0.0 (dnsmasq addn-hosts consumes this).
awk '{print "0.0.0.0 " $0}' "$tmp" > "$OUT"
rm -f "$tmp" "$raw"
