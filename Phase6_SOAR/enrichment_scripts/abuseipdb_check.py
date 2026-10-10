#!/usr/bin/env python3
"""
AbuseIPDB Reputation Check Script.
Queries AbuseIPDB API v2 for IP abuse reports and confidence scores.

Author: Vignesh R
Usage:
    python3 abuseipdb_check.py --ip 203.0.113.50
    python3 abuseipdb_check.py --ip 203.0.113.50 --days 90
    python3 abuseipdb_check.py --file suspicious_ips.txt --output results.json

Requires: ABUSEIPDB_API_KEY environment variable
Rate limit: 1000 checks/day on free tier
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error
import urllib.parse


ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2"


def check_ip(ip: str, api_key: str, max_age_days: int = 90) -> dict:
    """Check a single IP against AbuseIPDB."""
    params = urllib.parse.urlencode({
        "ipAddress": ip,
        "maxAgeInDays": max_age_days,
        "verbose": ""
    })
    url = f"{ABUSEIPDB_API}/check?{params}"

    req = urllib.request.Request(url)
    req.add_header("Key", api_key)
    req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            result = data.get("data", {})
            return {
                "ip": result.get("ipAddress", ip),
                "is_public": result.get("isPublic", False),
                "abuse_confidence_score": result.get("abuseConfidenceScore", 0),
                "country": result.get("countryCode", "N/A"),
                "isp": result.get("isp", "N/A"),
                "domain": result.get("domain", "N/A"),
                "total_reports": result.get("totalReports", 0),
                "num_distinct_users": result.get("numDistinctUsers", 0),
                "last_reported": result.get("lastReportedAt", "Never"),
                "is_tor": result.get("isTor", False),
                "verdict": (
                    "MALICIOUS" if result.get("abuseConfidenceScore", 0) > 75
                    else "SUSPICIOUS" if result.get("abuseConfidenceScore", 0) > 25
                    else "CLEAN"
                ),
            }
    except urllib.error.HTTPError as e:
        return {"ip": ip, "error": f"HTTP {e.code}: {e.reason}"}
    except urllib.error.URLError as e:
        return {"ip": ip, "error": str(e.reason)}


def main():
    parser = argparse.ArgumentParser(description="AbuseIPDB IP reputation check")
    parser.add_argument("--ip", help="Single IP to check")
    parser.add_argument("--file", help="File with IPs (one per line)")
    parser.add_argument("--days", type=int, default=90, help="Max age of reports in days")
    parser.add_argument("--output", help="Output JSON file")
    parser.add_argument("--api-key", help="API key (or set ABUSEIPDB_API_KEY)")
    args = parser.parse_args()

    if not args.ip and not args.file:
        parser.print_help()
        sys.exit(1)

    api_key = args.api_key or os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        print("[!] Set ABUSEIPDB_API_KEY or pass --api-key")
        sys.exit(1)

    results = []

    if args.ip:
        result = check_ip(args.ip, api_key, args.days)
        results.append(result)
        print(f"\n=== AbuseIPDB Report: {args.ip} ===")
        print(f"  Abuse Score:    {result.get('abuse_confidence_score', 'N/A')}%")
        print(f"  Total Reports:  {result.get('total_reports', 'N/A')}")
        print(f"  Country:        {result.get('country', 'N/A')}")
        print(f"  ISP:            {result.get('isp', 'N/A')}")
        print(f"  Is Tor:         {result.get('is_tor', 'N/A')}")
        print(f"  Verdict:        {result.get('verdict', 'N/A')}")

    if args.file:
        with open(args.file, "r") as f:
            for line in f:
                ip = line.strip()
                if not ip or ip.startswith("#"):
                    continue
                result = check_ip(ip, api_key, args.days)
                results.append(result)
                print(f"  {ip}: score={result.get('abuse_confidence_score', '?')}% verdict={result.get('verdict', '?')}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[*] Results written to {args.output}")


if __name__ == "__main__":
    main()
