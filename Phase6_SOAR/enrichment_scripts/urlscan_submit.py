#!/usr/bin/env python3
"""
URLScan.io Submission and Result Retrieval Script.
Submits URLs for scanning and retrieves analysis results.

Author: Vignesh R
Usage:
    python3 urlscan_submit.py --submit "https://suspicious-site.com/login"
    python3 urlscan_submit.py --result <scan-uuid>
    python3 urlscan_submit.py --search "domain:example.com"

Requires: URLSCAN_API_KEY environment variable
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error


URLSCAN_API = "https://urlscan.io/api/v1"


def submit_url(url: str, api_key: str, visibility: str = "unlisted") -> dict:
    """Submit a URL for scanning."""
    data = json.dumps({"url": url, "visibility": visibility}).encode()

    req = urllib.request.Request(f"{URLSCAN_API}/scan/", data=data, method="POST")
    req.add_header("API-Key", api_key)
    req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
            print(f"\n[*] Scan submitted successfully")
            print(f"  UUID:       {result.get('uuid', 'N/A')}")
            print(f"  Result URL: {result.get('result', 'N/A')}")
            print(f"  API URL:    {result.get('api', 'N/A')}")
            print(f"\n[*] Scan processing — wait 15-30 seconds then use --result {result.get('uuid', '')}")
            return result
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        return {"error": f"HTTP {e.code}: {e.reason}", "detail": body}
    except urllib.error.URLError as e:
        return {"error": str(e.reason)}


def get_result(uuid: str) -> dict:
    """Retrieve scan results by UUID."""
    req = urllib.request.Request(f"{URLSCAN_API}/result/{uuid}/")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            page = data.get("page", {})
            verdicts = data.get("verdicts", {}).get("overall", {})
            stats = data.get("stats", {})

            print(f"\n=== URLScan.io Report: {uuid} ===")
            print(f"  URL:         {page.get('url', 'N/A')}")
            print(f"  Domain:      {page.get('domain', 'N/A')}")
            print(f"  IP:          {page.get('ip', 'N/A')}")
            print(f"  Country:     {page.get('country', 'N/A')}")
            print(f"  Server:      {page.get('server', 'N/A')}")
            print(f"  Score:       {verdicts.get('score', 'N/A')}")
            print(f"  Malicious:   {verdicts.get('malicious', 'N/A')}")
            print(f"  Categories:  {verdicts.get('categories', [])}")
            print(f"  IPs:         {stats.get('uniqIPs', 'N/A')} unique")
            print(f"  Requests:    {stats.get('requests', 'N/A')}")
            return data
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"error": "Scan not ready yet — try again in a few seconds"}
        return {"error": f"HTTP {e.code}: {e.reason}"}


def search_scans(query: str, api_key: str) -> dict:
    """Search previous scans."""
    encoded = urllib.parse.quote(query)
    req = urllib.request.Request(f"{URLSCAN_API}/search/?q={encoded}")
    req.add_header("API-Key", api_key)

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            results = data.get("results", [])
            print(f"\n[*] Found {len(results)} matching scans")
            for r in results[:5]:
                page = r.get("page", {})
                print(f"  {page.get('url', 'N/A')} — {r.get('_id', 'N/A')}")
            return data
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.reason}"}


def main():
    parser = argparse.ArgumentParser(description="URLScan.io submission and lookup")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--submit", metavar="URL", help="Submit URL for scanning")
    group.add_argument("--result", metavar="UUID", help="Get scan results by UUID")
    group.add_argument("--search", metavar="QUERY", help="Search previous scans")
    parser.add_argument("--visibility", default="unlisted", choices=["public", "unlisted", "private"])
    parser.add_argument("--api-key", help="API key (or set URLSCAN_API_KEY)")
    parser.add_argument("--output", help="Output JSON file")
    args = parser.parse_args()

    api_key = args.api_key or os.environ.get("URLSCAN_API_KEY")
    if not api_key and (args.submit or args.search):
        print("[!] Set URLSCAN_API_KEY or pass --api-key")
        sys.exit(1)

    if args.submit:
        result = submit_url(args.submit, api_key, args.visibility)
    elif args.result:
        result = get_result(args.result)
    elif args.search:
        result = search_scans(args.search, api_key)

    if args.output and result:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\n[*] Full results written to {args.output}")


if __name__ == "__main__":
    import urllib.parse
    main()
