#!/bin/bash
#
# extra_feeds.sh — append public IP threat feeds (as CIDR lines) to the deny list.
#
# Feeds (all public, no key): FireHOL level1, Spamhaus DROP + EDROP,
# abuse.ch Feodo C2, Tor exit nodes. A feed being unreachable is tolerated
# (its fetch just yields nothing). Output is merged + deduped by the workflow.
#
set -u
OUT="${1:-deny_lists/combined_deny.txt}"
tmp="$(mktemp)"
fetch(){ curl -fsSL --retry 2 --connect-timeout 15 --max-time 40 "$1" 2>/dev/null || true; }

{
  fetch "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
  fetch "https://www.spamhaus.org/drop/drop.txt"  | sed -E 's/;.*//'
  fetch "https://www.spamhaus.org/drop/edrop.txt" | sed -E 's/;.*//'
  fetch "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
  fetch "https://check.torproject.org/torbulkexitlist"
} 2>/dev/null \
  | grep -vE '^[[:space:]]*#' \
  | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' \
  | awk '{ if ($0 !~ /\//) $0 = $0 "/32"; print }' \
  | sort -u > "$tmp"

n=$(wc -l < "$tmp" | tr -d ' ')
echo "extra feeds: ${n} prefixes" >&2
cat "$tmp" >> "$OUT"
rm -f "$tmp"
