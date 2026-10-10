#!/usr/bin/env python3
"""
pfSense Firewall Block Script for Brute Force Response Playbook.
Adds or removes IP addresses from pfSense firewall block alias via API.

Author: Vignesh R
MITRE ATT&CK: T1110 (Brute Force) — Automated Response

Usage:
    python3 pfsense_block_script.py --block 203.0.113.50
    python3 pfsense_block_script.py --unblock 203.0.113.50
    python3 pfsense_block_script.py --list

Requires:
    PFSENSE_HOST, PFSENSE_API_KEY, PFSENSE_API_SECRET environment variables
    pfSense REST API package installed on the firewall

WARNING: This script modifies live firewall rules.
         Test in lab environment before production deployment.
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error
import ssl
from datetime import datetime, timezone


def get_config() -> dict:
    """Load pfSense connection configuration from environment."""
    host = os.environ.get("PFSENSE_HOST")
    api_key = os.environ.get("PFSENSE_API_KEY")
    api_secret = os.environ.get("PFSENSE_API_SECRET")

    if not all([host, api_key, api_secret]):
        print("[!] Error: pfSense configuration required.")
        print("    Set PFSENSE_HOST, PFSENSE_API_KEY, PFSENSE_API_SECRET")
        sys.exit(1)

    return {"host": host, "api_key": api_key, "api_secret": api_secret}


def is_internal_ip(ip: str) -> bool:
    """Safety check — never auto-block internal IPs."""
    octets = ip.split(".")
    if len(octets) != 4:
        return False
    try:
        first, second = int(octets[0]), int(octets[1])
    except ValueError:
        return False
    return (
        first == 10
        or (first == 172 and 16 <= second <= 31)
        or (first == 192 and second == 168)
        or first == 127
    )


def pfsense_api_call(
    config: dict, endpoint: str, method: str = "GET", data: dict | None = None
) -> dict:
    """Make authenticated request to pfSense REST API."""
    url = f"https://{config['host']}/api/v1/{endpoint}"
    headers = {
        "Authorization": f"{config['api_key']} {config['api_secret']}",
        "Content-Type": "application/json",
    }

    # Lab environment: self-signed cert handling
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, method=method, headers=headers)
    if data:
        req.data = json.dumps(data).encode()

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.reason}"}
    except urllib.error.URLError as e:
        return {"error": f"Connection error: {e.reason}"}


def block_ip(ip: str, config: dict, reason: str = "Brute force auto-block") -> dict:
    """Add IP to pfSense firewall block alias."""
    if is_internal_ip(ip):
        return {
            "status": "REFUSED",
            "ip": ip,
            "reason": "Internal IP — manual investigation required",
        }

    # Add to alias (block list)
    data = {
        "name": "SOC_Blocklist",
        "address": ip,
        "descr": f"{reason} | {datetime.now(timezone.utc).isoformat()} | Analyst: Vignesh R",
        "type": "host",
        "apply": True,
    }

    result = pfsense_api_call(config, "firewall/alias/entry", method="POST", data=data)

    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": "BLOCK",
        "ip": ip,
        "reason": reason,
        "result": result,
    }

    # Append to local audit log
    with open("block_audit_log.json", "a") as f:
        f.write(json.dumps(log_entry) + "\n")

    return log_entry


def unblock_ip(ip: str, config: dict) -> dict:
    """Remove IP from pfSense firewall block alias."""
    data = {"name": "SOC_Blocklist", "address": ip, "apply": True}

    result = pfsense_api_call(
        config, "firewall/alias/entry", method="DELETE", data=data
    )

    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": "UNBLOCK",
        "ip": ip,
        "result": result,
    }

    with open("block_audit_log.json", "a") as f:
        f.write(json.dumps(log_entry) + "\n")

    return log_entry


def list_blocked(config: dict) -> dict:
    """List all IPs in the SOC_Blocklist alias."""
    return pfsense_api_call(config, "firewall/alias")


def main():
    parser = argparse.ArgumentParser(description="pfSense IP block management")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--block", metavar="IP", help="Block an IP address")
    group.add_argument("--unblock", metavar="IP", help="Unblock an IP address")
    group.add_argument("--list", action="store_true", help="List blocked IPs")
    parser.add_argument("--reason", default="Brute force auto-block", help="Block reason")
    args = parser.parse_args()

    config = get_config()

    if args.block:
        print(f"[*] Blocking {args.block}...")
        result = block_ip(args.block, config, args.reason)
        print(json.dumps(result, indent=2))
    elif args.unblock:
        print(f"[*] Unblocking {args.unblock}...")
        result = unblock_ip(args.unblock, config)
        print(json.dumps(result, indent=2))
    elif args.list:
        print("[*] Retrieving block list...")
        result = list_blocked(config)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
