#!/usr/bin/env python3
"""
VirusTotal Enrichment Script for Phishing Triage Playbook.
Checks URLs and file hashes against VirusTotal API v3.

Author: Vignesh R
Usage:
    python3 vt_enrichment.py --url "https://suspicious-domain.com/payload"
    python3 vt_enrichment.py --hash "e3b0c44298fc1c149afbf4c8996fb924..."
    python3 vt_enrichment.py --file iocs.txt  (one IOC per line)

Requires: VT_API_KEY environment variable or --api-key argument
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error


VT_API_BASE = "https://www.virustotal.com/api/v3"


def get_api_key(cli_key: str | None = None) -> str:
    """Retrieve VirusTotal API key from argument or environment."""
    key = cli_key or os.environ.get("VT_API_KEY")
    if not key:
        print("[!] Error: VirusTotal API key required.")
        print("    Set VT_API_KEY environment variable or use --api-key")
        sys.exit(1)
    return key


def vt_request(endpoint: str, api_key: str) -> dict:
    """Make authenticated GET request to VirusTotal API v3."""
    url = f"{VT_API_BASE}/{endpoint}"
    req = urllib.request.Request(url)
    req.add_header("x-apikey", api_key)
    req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"error": "not_found"}
        if e.code == 429:
            print("[!] Rate limit hit — waiting 60 seconds...")
            time.sleep(60)
            return vt_request(endpoint, api_key)
        return {"error": f"HTTP {e.code}: {e.reason}"}
    except urllib.error.URLError as e:
        return {"error": f"Connection error: {e.reason}"}


def check_url(url: str, api_key: str) -> dict:
    """Check a URL against VirusTotal."""
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    result = vt_request(f"urls/{url_id}", api_key)

    if "error" in result:
        return {"ioc": url, "type": "url", "status": result["error"]}

    stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {
        "ioc": url,
        "type": "url",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "verdict": classify_verdict(stats),
    }


def check_hash(file_hash: str, api_key: str) -> dict:
    """Check a file hash against VirusTotal."""
    result = vt_request(f"files/{file_hash}", api_key)

    if "error" in result:
        return {"ioc": file_hash, "type": "hash", "status": result["error"]}

    attrs = result.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "ioc": file_hash,
        "type": "hash",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "file_type": attrs.get("type_description", "unknown"),
        "verdict": classify_verdict(stats),
    }


def classify_verdict(stats: dict) -> str:
    """Classify VT results into risk levels for SOAR decision logic."""
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious >= 5:
        return "MALICIOUS"
    if malicious >= 1 or suspicious >= 3:
        return "SUSPICIOUS"
    return "CLEAN"


def main():
    parser = argparse.ArgumentParser(description="VirusTotal IOC enrichment")
    parser.add_argument("--url", help="URL to check")
    parser.add_argument("--hash", help="File hash (MD5/SHA1/SHA256) to check")
    parser.add_argument("--file", help="File containing IOCs (one per line)")
    parser.add_argument("--api-key", help="VirusTotal API key")
    parser.add_argument(
        "--output", default=None, help="Output JSON file (default: stdout)"
    )
    args = parser.parse_args()

    if not any([args.url, args.hash, args.file]):
        parser.print_help()
        sys.exit(1)

    api_key = get_api_key(args.api_key)
    results = []

    if args.url:
        results.append(check_url(args.url, api_key))
    if args.hash:
        results.append(check_hash(args.hash, api_key))
    if args.file:
        with open(args.file, "r") as f:
            for line in f:
                ioc = line.strip()
                if not ioc or ioc.startswith("#"):
                    continue
                if ioc.startswith("http"):
                    results.append(check_url(ioc, api_key))
                else:
                    results.append(check_hash(ioc, api_key))
                time.sleep(15)  # Free API rate limit: 4 requests/minute

    output = json.dumps(results, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"[*] Results written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
