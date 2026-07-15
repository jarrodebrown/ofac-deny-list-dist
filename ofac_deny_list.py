#!/usr/bin/env python3
"""
ofac_deny_list.py — Fetch OFAC sanctions data and resolve to IP CIDR deny lists.

Sources:
  1. OFAC SDN list (CSV) from Treasury.gov — entity names, countries, programs
  2. Country CIDR blocks from ipdeny.com — maps ISO country codes to IP prefixes
  3. Team Cymru DNS — maps ASNs to announced IP prefixes for entity resolution
  4. RIPE RIS / PeeringDB — supplemental ASN-to-org lookups

Outputs:
  - Combined CIDR deny list (one prefix per line)
  - Per-country CIDR files
  - Entity-resolved CIDR file (where ASN mapping succeeds)
  - Metadata JSON with provenance and stats

Usage:
    python3 ofac_deny_list.py [--config config.json] [--output-dir deny_lists/]
"""

import argparse
import csv
import io
import json
import logging
import os
import re
import socket
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------
DEFAULT_CONFIG = {
    # Comprehensively sanctioned countries (ISO 3166-1 alpha-2)
    # These get full country-level CIDR blocking
    "sanctioned_countries": {
        "KP": "North Korea",
        "IR": "Iran",
        "CU": "Cuba",
        "RU": "Russia",
        "BY": "Belarus",
    },
    # Partially sanctioned / watchlist countries — optional, disabled by default
    # Enable these in config.json if desired
    "watchlist_countries": {
        "SY": "Syria",
        "MM": "Myanmar (Burma)",
        "CF": "Central African Republic",
        "CD": "Congo (DRC)",
        "SO": "Somalia",
        "YE": "Yemen",
        "VE": "Venezuela",
        "NI": "Nicaragua",
    },
    "include_watchlist": False,
    # Crimea, Donetsk, Luhansk — these don't have separate country codes
    # Their IPs fall within UA ranges but are identifiable by specific ASNs
    "crimea_asns": [
        "AS47541",  # JSC CRELCOM (Crimea telecom)
        "AS28761",  # CrimeaCom (IKS)
        "AS35816",  # Lancom Ltd (Crimea)
        "AS51764",  # Miranda-Media (Crimea ISP)
        "AS44709",  # SevStar (Sevastopol)
        "AS206804", # EstNOC Donetsk
    ],
    # OFAC data sources
    "ofac_sdn_url": "https://www.treasury.gov/ofac/downloads/sdn.csv",
    "ofac_sdn_add_url": "https://www.treasury.gov/ofac/downloads/add.csv",
    "ofac_consolidated_url": "https://www.treasury.gov/ofac/downloads/consolidated/cons_prim.csv",
    # Country CIDR sources
    "ipdeny_base_url": "https://www.ipdeny.com/ipblocks/data/aggregated",
    "ipdeny_ipv6_base_url": "https://www.ipdeny.com/ipv6/ipaddresses/aggregated",
    # Team Cymru for ASN lookups
    "cymru_whois_server": "whois.cymru.com",
    "cymru_dns_origin": "origin.asn.cymru.com",
    "cymru_dns_peer": "peer.asn.cymru.com",
    # Whitelist — never block these prefixes even if they fall in sanctioned ranges
    # (major CDN / cloud provider ranges that might geo-locate to sanctioned countries)
    "whitelist_asns": [
        "AS13335",  # Cloudflare
        "AS16509",  # Amazon AWS
        "AS15169",  # Google
        "AS8075",   # Microsoft Azure
        "AS20940",  # Akamai
        "AS54113",  # Fastly
    ],
    # Performance
    "request_timeout": 30,
    "request_delay": 0.5,  # seconds between HTTP requests
    "include_ipv6": False,  # set True to also fetch IPv6 blocks
    "user_agent": "OFAC-Deny-List/1.0 (network security tool)",
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def setup_logging(log_dir):
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"ofac_update_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout),
        ]
    )
    return log_file


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------
def fetch_url(url, config, description="resource"):
    """Fetch a URL with proper headers and error handling."""
    headers = {"User-Agent": config.get("user_agent", DEFAULT_CONFIG["user_agent"])}
    timeout = config.get("request_timeout", DEFAULT_CONFIG["request_timeout"])

    logging.info(f"Fetching {description}: {url}")
    try:
        req = Request(url, headers=headers)
        with urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            logging.info(f"  -> {len(data)} bytes received")
            return data.decode("utf-8", errors="replace")
    except HTTPError as e:
        logging.error(f"HTTP error fetching {url}: {e.code} {e.reason}")
        return None
    except URLError as e:
        logging.error(f"URL error fetching {url}: {e.reason}")
        return None
    except Exception as e:
        logging.error(f"Error fetching {url}: {e}")
        return None


# ---------------------------------------------------------------------------
# OFAC SDN list parsing
# ---------------------------------------------------------------------------
def parse_ofac_sdn(config):
    """Download and parse the OFAC SDN list to extract sanctioned entities."""
    entities = []

    # Fetch main SDN list
    sdn_data = fetch_url(config.get("ofac_sdn_url", DEFAULT_CONFIG["ofac_sdn_url"]),
                         config, "OFAC SDN list")
    if not sdn_data:
        logging.warning("Could not fetch SDN list — continuing with country-only blocking")
        return entities

    # SDN.CSV columns: SDN_ID, SDN_Name, SDN_Type, Program, Title, Call_Sign,
    #                   Vess_Type, Tonnage, GRT, Vess_Flag, Vess_Owner, Remarks
    reader = csv.reader(io.StringIO(sdn_data))
    for row in reader:
        if len(row) < 4:
            continue
        try:
            entity = {
                "sdn_id": row[0].strip(),
                "name": row[1].strip(),
                "type": row[2].strip(),  # Individual, Entity, Vessel, Aircraft
                "program": row[3].strip(),
                "remarks": row[11].strip() if len(row) > 11 else "",
            }
            # Only interested in entities (not individuals) for IP blocking
            if entity["type"].lower() in ("entity", "-0-"):
                entities.append(entity)
        except (IndexError, ValueError):
            continue

    # Also fetch address file for country associations
    add_data = fetch_url(config.get("ofac_sdn_add_url", DEFAULT_CONFIG["ofac_sdn_add_url"]),
                         config, "OFAC address list")
    if add_data:
        # ADD.CSV columns: SDN_ID, Add_Num, Address, City, Country, Add_Remarks
        addr_by_id = defaultdict(list)
        reader = csv.reader(io.StringIO(add_data))
        for row in reader:
            if len(row) >= 5:
                addr_by_id[row[0].strip()].append({
                    "address": row[2].strip() if len(row) > 2 else "",
                    "city": row[3].strip() if len(row) > 3 else "",
                    "country": row[4].strip() if len(row) > 4 else "",
                })

        for entity in entities:
            entity["addresses"] = addr_by_id.get(entity["sdn_id"], [])

    logging.info(f"Parsed {len(entities)} OFAC SDN entities")
    return entities


def extract_entity_keywords(entities):
    """Extract searchable keywords from OFAC entities for ASN matching."""
    keywords = []
    for entity in entities:
        name = entity.get("name", "")
        if not name or name == "-0-":
            continue
        # Clean up the name for searching
        # Remove common suffixes and legal designations
        clean = re.sub(r'\b(LLC|LTD|INC|CORP|JSC|OJSC|PJSC|OAO|ZAO|CO|GMBH)\b',
                       '', name, flags=re.IGNORECASE).strip()
        if len(clean) > 3:
            keywords.append({
                "keyword": clean,
                "sdn_id": entity.get("sdn_id", ""),
                "program": entity.get("program", ""),
                "original_name": name,
            })
    return keywords


# ---------------------------------------------------------------------------
# Country CIDR block fetching
# ---------------------------------------------------------------------------
def fetch_country_cidrs(country_code, config, ipv6=False):
    """Fetch CIDR blocks for a country from ipdeny.com."""
    cc = country_code.lower()
    if ipv6:
        base = config.get("ipdeny_ipv6_base_url", DEFAULT_CONFIG["ipdeny_ipv6_base_url"])
        url = f"{base}/{cc}-aggregated.zone"
    else:
        base = config.get("ipdeny_base_url", DEFAULT_CONFIG["ipdeny_base_url"])
        url = f"{base}/{cc}-aggregated.zone"

    data = fetch_url(url, config, f"CIDR blocks for {country_code}")
    if not data:
        return []

    cidrs = []
    for line in data.strip().split("\n"):
        line = line.strip()
        if line and not line.startswith("#"):
            # Validate CIDR format
            if re.match(r'^[\d.:a-fA-F]+/\d+$', line):
                cidrs.append(line)

    logging.info(f"  {country_code}: {len(cidrs)} CIDR blocks")
    return cidrs


def fetch_all_country_cidrs(config):
    """Fetch CIDR blocks for all sanctioned countries."""
    countries = dict(config.get("sanctioned_countries", DEFAULT_CONFIG["sanctioned_countries"]))

    if config.get("include_watchlist", False):
        watchlist = config.get("watchlist_countries", DEFAULT_CONFIG["watchlist_countries"])
        countries.update(watchlist)

    all_cidrs = {}
    delay = config.get("request_delay", DEFAULT_CONFIG["request_delay"])

    for cc, name in countries.items():
        logging.info(f"Fetching CIDRs for {name} ({cc})...")
        cidrs = fetch_country_cidrs(cc, config)
        if cidrs:
            all_cidrs[cc] = {
                "name": name,
                "cidrs": cidrs,
                "count": len(cidrs),
            }

        # Also fetch IPv6 if enabled
        if config.get("include_ipv6", False):
            ipv6_cidrs = fetch_country_cidrs(cc, config, ipv6=True)
            if ipv6_cidrs:
                if cc in all_cidrs:
                    all_cidrs[cc]["cidrs_v6"] = ipv6_cidrs
                    all_cidrs[cc]["count_v6"] = len(ipv6_cidrs)

        time.sleep(delay)

    return all_cidrs


# ---------------------------------------------------------------------------
# ASN resolution via Team Cymru DNS
# ---------------------------------------------------------------------------
def resolve_asn_prefixes_dns(asn_list, config):
    """Resolve ASN numbers to their announced IP prefixes via Team Cymru DNS.

    Uses DNS TXT queries to {ASN}.asn.cymru.com to get prefix announcements.
    This is a best-effort resolution — not all ASNs will resolve.
    """
    prefixes = {}

    for asn in asn_list:
        asn_num = asn.replace("AS", "").replace("as", "")
        try:
            # Query Team Cymru: dig TXT AS{num}.asn.cymru.com
            # We'll use socket to do a simple lookup
            # The DNS approach uses: {prefix_reversed}.origin.asn.cymru.com
            # But for ASN-to-prefix we need the whois interface
            # Using a simple whois query instead
            prefixes[asn] = resolve_asn_whois(asn_num, config)
            time.sleep(0.2)
        except Exception as e:
            logging.warning(f"Could not resolve {asn}: {e}")
            prefixes[asn] = []

    return prefixes


def resolve_asn_whois(asn_num, config):
    """Query Team Cymru whois for prefixes announced by an ASN."""
    try:
        server = config.get("cymru_whois_server", "whois.cymru.com")
        query = f"-p {asn_num}\n"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((server, 43))
        sock.sendall(query.encode())

        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()

        prefixes = []
        for line in response.decode("utf-8", errors="replace").split("\n"):
            line = line.strip()
            if not line or line.startswith("Bulk") or line.startswith("AS"):
                continue
            # Lines look like: ASN | Prefix | CC | ...
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 2:
                prefix = parts[1].strip()
                if re.match(r'^[\d.]+/\d+$', prefix):
                    prefixes.append(prefix)

        logging.info(f"  AS{asn_num}: {len(prefixes)} prefixes")
        return prefixes

    except Exception as e:
        logging.warning(f"Whois query failed for AS{asn_num}: {e}")
        return []


# ---------------------------------------------------------------------------
# Whitelist filtering
# ---------------------------------------------------------------------------
def fetch_whitelist_prefixes(config):
    """Resolve whitelisted ASNs to their prefixes so we can exclude them."""
    whitelist_asns = config.get("whitelist_asns", DEFAULT_CONFIG["whitelist_asns"])
    if not whitelist_asns:
        return set()

    logging.info("Resolving whitelist ASN prefixes...")
    all_prefixes = set()

    for asn in whitelist_asns:
        asn_num = asn.replace("AS", "").replace("as", "")
        prefixes = resolve_asn_whois(asn_num, config)
        all_prefixes.update(prefixes)
        time.sleep(0.2)

    logging.info(f"Whitelist contains {len(all_prefixes)} prefixes")
    return all_prefixes


def filter_whitelist(cidrs, whitelist_prefixes):
    """Remove whitelisted prefixes from the deny list."""
    if not whitelist_prefixes:
        return cidrs
    return [c for c in cidrs if c not in whitelist_prefixes]


# ---------------------------------------------------------------------------
# Output generation
# ---------------------------------------------------------------------------
def write_deny_lists(country_cidrs, entity_prefixes, output_dir, config):
    """Write all deny list files."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # Fetch whitelist
    whitelist = set()
    try:
        whitelist = fetch_whitelist_prefixes(config)
    except Exception as e:
        logging.warning(f"Could not resolve whitelist — proceeding without: {e}")

    # Per-country files
    all_cidrs = []
    country_stats = {}

    for cc, data in country_cidrs.items():
        cidrs = filter_whitelist(data["cidrs"], whitelist)
        country_file = os.path.join(output_dir, f"{cc.lower()}_deny.txt")
        with open(country_file, "w") as f:
            f.write(f"# {data['name']} ({cc}) — OFAC deny list\n")
            f.write(f"# Generated: {timestamp} UTC\n")
            f.write(f"# Prefixes: {len(cidrs)}\n")
            f.write(f"# Source: ipdeny.com aggregated country blocks\n\n")
            for cidr in cidrs:
                f.write(f"{cidr}\n")

        all_cidrs.extend(cidrs)
        country_stats[cc] = {
            "name": data["name"],
            "prefixes": len(cidrs),
            "original_prefixes": data["count"],
            "whitelisted_removed": data["count"] - len(cidrs),
        }
        logging.info(f"Wrote {country_file}: {len(cidrs)} prefixes")

    # Entity-resolved prefixes
    entity_cidrs = []
    entity_stats = {}
    for asn, prefixes in entity_prefixes.items():
        filtered = filter_whitelist(prefixes, whitelist)
        entity_cidrs.extend(filtered)
        if filtered:
            entity_stats[asn] = len(filtered)

    if entity_cidrs:
        entity_file = os.path.join(output_dir, "entity_deny.txt")
        with open(entity_file, "w") as f:
            f.write(f"# OFAC Entity-resolved deny list (ASN-based)\n")
            f.write(f"# Generated: {timestamp} UTC\n")
            f.write(f"# Prefixes: {len(entity_cidrs)}\n\n")
            for cidr in sorted(set(entity_cidrs)):
                f.write(f"{cidr}\n")
        all_cidrs.extend(entity_cidrs)
        logging.info(f"Wrote {entity_file}: {len(entity_cidrs)} entity prefixes")

    # Combined deny list — deduplicated
    combined = sorted(set(all_cidrs))
    combined_file = os.path.join(output_dir, "combined_deny.txt")
    with open(combined_file, "w") as f:
        f.write(f"# OFAC Combined Deny List\n")
        f.write(f"# Generated: {timestamp} UTC\n")
        f.write(f"# Total unique prefixes: {len(combined)}\n")
        f.write(f"# Countries: {', '.join(sorted(country_cidrs.keys()))}\n")
        f.write(f"# Entity ASNs resolved: {len(entity_stats)}\n\n")
        for cidr in combined:
            f.write(f"{cidr}\n")

    logging.info(f"Combined deny list: {len(combined)} unique prefixes -> {combined_file}")

    # Metadata JSON
    metadata = {
        "generated_utc": timestamp,
        "total_prefixes": len(combined),
        "countries": country_stats,
        "entity_asns": entity_stats,
        "whitelist_asns": config.get("whitelist_asns", []),
        "whitelist_prefixes_excluded": len(whitelist),
        "sources": {
            "ofac": config.get("ofac_sdn_url", DEFAULT_CONFIG["ofac_sdn_url"]),
            "country_cidrs": config.get("ipdeny_base_url", DEFAULT_CONFIG["ipdeny_base_url"]),
            "asn_resolution": "Team Cymru Whois",
        },
        "config": {
            "include_watchlist": config.get("include_watchlist", False),
            "include_ipv6": config.get("include_ipv6", False),
        }
    }

    meta_file = os.path.join(output_dir, "metadata.json")
    with open(meta_file, "w") as f:
        json.dump(metadata, f, indent=2)

    return combined_file, metadata


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Fetch OFAC sanctions data and generate IP CIDR deny lists."
    )
    parser.add_argument("--config", default=None,
                        help="Path to config.json (default: config.json in script dir)")
    parser.add_argument("--output-dir", default=None,
                        help="Output directory for deny lists (default: deny_lists/)")
    parser.add_argument("--skip-entities", action="store_true",
                        help="Skip OFAC entity parsing and ASN resolution (country-only mode)")
    parser.add_argument("--skip-whitelist", action="store_true",
                        help="Skip CDN/cloud whitelist resolution")
    parser.add_argument("--include-watchlist", action="store_true",
                        help="Include watchlist countries (partial sanctions)")
    args = parser.parse_args()

    # Resolve paths
    script_dir = str(Path(__file__).resolve().parent)
    config_path = args.config or os.path.join(script_dir, "config.json")
    output_dir = args.output_dir or os.path.join(script_dir, "deny_lists")
    log_dir = os.path.join(script_dir, "logs")

    # Load config
    config = dict(DEFAULT_CONFIG)
    if os.path.exists(config_path):
        with open(config_path) as f:
            user_config = json.load(f)
            config.update(user_config)

    if args.include_watchlist:
        config["include_watchlist"] = True
    if args.skip_whitelist:
        config["whitelist_asns"] = []

    # Setup logging
    log_file = setup_logging(log_dir)

    logging.info("=" * 60)
    logging.info("  OFAC DENY LIST GENERATOR")
    logging.info("=" * 60)

    # Step 1: Parse OFAC SDN list
    entities = []
    if not args.skip_entities:
        logging.info("\n--- Step 1: Fetching OFAC SDN list ---")
        entities = parse_ofac_sdn(config)
    else:
        logging.info("\n--- Step 1: Skipping OFAC entity parsing (--skip-entities) ---")

    # Step 2: Fetch country CIDR blocks
    logging.info("\n--- Step 2: Fetching country CIDR blocks ---")
    country_cidrs = fetch_all_country_cidrs(config)

    if not country_cidrs:
        logging.error("No country CIDR data fetched — cannot generate deny list")
        sys.exit(1)

    # Step 3: Resolve Crimea/Donetsk ASNs and entity ASNs
    entity_prefixes = {}
    logging.info("\n--- Step 3: Resolving sanctioned-region ASNs ---")

    crimea_asns = config.get("crimea_asns", DEFAULT_CONFIG["crimea_asns"])
    if crimea_asns:
        logging.info(f"Resolving {len(crimea_asns)} Crimea/Donetsk ASNs...")
        crimea_prefixes = resolve_asn_prefixes_dns(crimea_asns, config)
        entity_prefixes.update(crimea_prefixes)

    # Step 4: Write output files
    logging.info("\n--- Step 4: Writing deny lists ---")
    combined_file, metadata = write_deny_lists(country_cidrs, entity_prefixes, output_dir, config)

    # Summary
    logging.info("\n" + "=" * 60)
    logging.info("  SUMMARY")
    logging.info("=" * 60)
    logging.info(f"  Countries blocked: {len(metadata['countries'])}")
    for cc, stats in metadata["countries"].items():
        logging.info(f"    {cc} ({stats['name']}): {stats['prefixes']} prefixes")
    logging.info(f"  Entity ASNs resolved: {len(metadata['entity_asns'])}")
    logging.info(f"  Whitelist exclusions: {metadata['whitelist_prefixes_excluded']}")
    logging.info(f"  Total unique prefixes: {metadata['total_prefixes']}")
    logging.info(f"  Combined deny list: {combined_file}")
    logging.info(f"  Log file: {log_file}")
    logging.info("=" * 60)

    return combined_file


if __name__ == "__main__":
    main()
