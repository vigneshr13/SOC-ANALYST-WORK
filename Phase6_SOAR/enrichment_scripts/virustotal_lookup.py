#!/usr/bin/env python3
"""
VirusTotal API v3 Lookup Script.
Standalone enrichment script for IP, domain, URL, and file hash lookups.

Author: Vignesh R
Usage:
    python3 virustotal_lookup.py --ip 8.8.8.8
    python3 virustotal_lookup.py --domain example.com
    python3 virustotal_lookup.py --hash <sha256>
    python3 virustotal_lookup.py --url "https://suspicious.site/path"

Requires: VT_API_KEY environment variable
Rate limit: 4 requests/minute on free tier
"""

import argparse
import base64
import json
import os
import sys
import time
import urllib.request
import urllib.error


VT_API_BASE = "https://www.virustotal.com/api/v3"


def vt_get(endpoint: str, api_key: str) -> dict:
    """Authenticated GET to VirusTotal API v3."""
    req = urllib.request.Request(f"{VT_API_BASE}/{endpoint}")
    req.add_header("x-apikey", api_key)
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"error": "not_found", "message": "No results in VirusTotal"}
        if e.code == 429:
            print("[!] Rate limited — waiting 60s...")
            time.sleep(60)
            return vt_get(endpoint, api_key)
        return {"error": f"HTTP {e.code}"}
    except urllib.error.URLError as e:
        return {"error": str(e.reason)}


def lookup_ip(ip: str, api_key: str) -> None:
    """Look up IP address reputation."""
    data = vt_get(f"ip_addresses/{ip}", api_key)
    if "error" in data:
        print(f"[!] {data['error']}")
        return
    attrs = data["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    print(f"\n=== VirusTotal IP Report: {ip} ===")
    print(f"  Country:     {attrs.get('country', 'N/A')}")
    print(f"  AS Owner:    {attrs.get('as_owner', 'N/A')}")
    print(f"  Malicious:   {stats.get('malicious', 0)}")
    print(f"  Suspicious:  {stats.get('suspicious', 0)}")
    print(f"  Harmless:    {stats.get('harmless', 0)}")
    print(f"  Undetected:  {stats.get('undetected', 0)}")


def lookup_domain(domain: str, api_key: str) -> None:
    """Look up domain reputation."""
    data = vt_get(f"domains/{domain}", api_key)
    if "error" in data:
        print(f"[!] {data['error']}")
        return
    attrs = data["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    print(f"\n=== VirusTotal Domain Report: {domain} ===")
    print(f"  Registrar:   {attrs.get('registrar', 'N/A')}")
    print(f"  Creation:    {attrs.get('creation_date', 'N/A')}")
    print(f"  Malicious:   {stats.get('malicious', 0)}")
    print(f"  Suspicious:  {stats.get('suspicious', 0)}")
    print(f"  Harmless:    {stats.get('harmless', 0)}")


def lookup_hash(file_hash: str, api_key: str) -> None:
    """Look up file hash."""
    data = vt_get(f"files/{file_hash}", api_key)
    if "error" in data:
        print(f"[!] {data['error']}")
        return
    attrs = data["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    print(f"\n=== VirusTotal File Report: {file_hash[:16]}... ===")
    print(f"  File Type:   {attrs.get('type_description', 'N/A')}")
    print(f"  File Size:   {attrs.get('size', 'N/A')} bytes")
    print(f"  File Name:   {attrs.get('meaningful_name', 'N/A')}")
    print(f"  Malicious:   {stats.get('malicious', 0)}")
    print(f"  Suspicious:  {stats.get('suspicious', 0)}")
    print(f"  Harmless:    {stats.get('harmless', 0)}")
    print(f"  Undetected:  {stats.get('undetected', 0)}")


def lookup_url(url: str, api_key: str) -> None:
    """Look up URL reputation."""
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    data = vt_get(f"urls/{url_id}", api_key)
    if "error" in data:
        print(f"[!] {data['error']}")
        return
    attrs = data["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    print(f"\n=== VirusTotal URL Report ===")
    print(f"  URL:         {attrs.get('url', url)}")
    print(f"  Final URL:   {attrs.get('last_final_url', 'N/A')}")
    print(f"  Malicious:   {stats.get('malicious', 0)}")
    print(f"  Suspicious:  {stats.get('suspicious', 0)}")
    print(f"  Harmless:    {stats.get('harmless', 0)}")


def main():
    parser = argparse.ArgumentParser(description="VirusTotal IOC lookup")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip", help="IP address to look up")
    group.add_argument("--domain", help="Domain to look up")
    group.add_argument("--hash", help="File hash to look up")
    group.add_argument("--url", help="URL to look up")
    parser.add_argument("--api-key", help="VT API key (or set VT_API_KEY env var)")
    args = parser.parse_args()

    api_key = args.api_key or os.environ.get("VT_API_KEY")
    if not api_key:
        print("[!] Set VT_API_KEY or pass --api-key")
        sys.exit(1)

    if args.ip:
        lookup_ip(args.ip, api_key)
    elif args.domain:
        lookup_domain(args.domain, api_key)
    elif args.hash:
        lookup_hash(args.hash, api_key)
    elif args.url:
        lookup_url(args.url, api_key)


if __name__ == "__main__":
    main()
