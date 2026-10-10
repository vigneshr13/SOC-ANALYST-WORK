#!/usr/bin/env python3
"""
DNS Beaconing Detection Script
Analyses Zeek conn.log for regular-interval connections to external IPs.

Author: Vignesh R
MITRE ATT&CK: T1071.004 (Application Layer Protocol: DNS)

Usage:
    python3 zeek_analysis.py --input conn.log --output beaconing_results.csv
    python3 zeek_analysis.py --input conn.log --threshold 0.1 --min-connections 20
"""

import argparse
import csv
import sys
from collections import defaultdict
from datetime import datetime
from statistics import mean, stdev


def parse_zeek_conn_log(filepath: str) -> list[dict]:
    """Parse Zeek conn.log (TSV format) into list of connection records."""
    connections = []
    with open(filepath, "r") as f:
        for line in f:
            if line.startswith("#"):
                continue
            fields = line.strip().split("\t")
            if len(fields) < 9:
                continue
            try:
                record = {
                    "ts": float(fields[0]),
                    "uid": fields[1],
                    "id_orig_h": fields[2],
                    "id_orig_p": fields[3],
                    "id_resp_h": fields[4],
                    "id_resp_p": fields[5],
                    "proto": fields[6],
                    "duration": fields[8] if fields[8] != "-" else "0",
                }
                connections.append(record)
            except (ValueError, IndexError):
                continue
    return connections


def is_internal_ip(ip: str) -> bool:
    """Check if an IP belongs to RFC 1918 private ranges."""
    octets = ip.split(".")
    if len(octets) != 4:
        return False
    try:
        first, second = int(octets[0]), int(octets[1])
    except ValueError:
        return False
    if first == 10:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    if first == 127:
        return True
    return False


def calculate_beaconing_score(timestamps: list[float]) -> dict:
    """
    Calculate beaconing score based on inter-connection interval regularity.

    A low coefficient of variation (CV) indicates regular-interval beaconing.
    CV < 0.1 = highly suspicious (very regular intervals)
    CV 0.1-0.3 = moderately suspicious
    CV > 0.3 = likely normal traffic
    """
    if len(timestamps) < 3:
        return {"score": 0.0, "cv": 1.0, "mean_interval": 0, "count": len(timestamps)}

    timestamps.sort()
    intervals = [
        timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)
    ]

    avg_interval = mean(intervals)
    if avg_interval == 0:
        return {"score": 0.0, "cv": 1.0, "mean_interval": 0, "count": len(timestamps)}

    std_interval = stdev(intervals) if len(intervals) > 1 else 0
    cv = std_interval / avg_interval if avg_interval > 0 else 1.0

    # Beaconing score: inverse of CV, capped at 1.0
    score = max(0.0, min(1.0, 1.0 - cv))

    return {
        "score": round(score, 4),
        "cv": round(cv, 4),
        "mean_interval": round(avg_interval, 2),
        "std_interval": round(std_interval, 2),
        "count": len(timestamps),
        "time_span_hours": round((timestamps[-1] - timestamps[0]) / 3600, 2),
    }


def detect_beaconing(
    connections: list[dict],
    cv_threshold: float = 0.1,
    min_connections: int = 20,
) -> list[dict]:
    """
    Group connections by (source_ip, dest_ip) and calculate beaconing scores.
    Returns suspicious pairs sorted by score (highest first).
    """
    # Group timestamps by (src, dst) pair
    pairs: dict[tuple[str, str], list[float]] = defaultdict(list)
    for conn in connections:
        src = conn["id_orig_h"]
        dst = conn["id_resp_h"]
        # Only analyse outbound connections to external IPs
        if is_internal_ip(src) and not is_internal_ip(dst):
            pairs[(src, dst)].append(conn["ts"])

    results = []
    for (src, dst), timestamps in pairs.items():
        if len(timestamps) < min_connections:
            continue
        metrics = calculate_beaconing_score(timestamps)
        if metrics["cv"] <= cv_threshold:
            results.append(
                {
                    "source_ip": src,
                    "dest_ip": dst,
                    "beaconing_score": metrics["score"],
                    "coefficient_of_variation": metrics["cv"],
                    "mean_interval_seconds": metrics["mean_interval"],
                    "std_interval_seconds": metrics["std_interval"],
                    "connection_count": metrics["count"],
                    "time_span_hours": metrics["time_span_hours"],
                    "assessment": "HIGH" if metrics["cv"] < 0.05 else "MEDIUM",
                }
            )

    results.sort(key=lambda x: x["beaconing_score"], reverse=True)
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Detect DNS/network beaconing from Zeek conn.log"
    )
    parser.add_argument("--input", required=True, help="Path to Zeek conn.log file")
    parser.add_argument(
        "--output", default="beaconing_results.csv", help="Output CSV file"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.1,
        help="CV threshold for beaconing detection (default: 0.1)",
    )
    parser.add_argument(
        "--min-connections",
        type=int,
        default=20,
        help="Minimum connections to analyse a pair (default: 20)",
    )
    args = parser.parse_args()

    print(f"[*] Parsing {args.input}...")
    connections = parse_zeek_conn_log(args.input)
    print(f"[*] Parsed {len(connections)} connection records")

    print(f"[*] Analysing beaconing patterns (CV threshold: {args.threshold})...")
    results = detect_beaconing(connections, args.threshold, args.min_connections)

    if results:
        print(f"\n[!] Found {len(results)} suspicious beaconing pairs:\n")
        for r in results:
            print(
                f"  {r['source_ip']} -> {r['dest_ip']} | "
                f"Score: {r['beaconing_score']} | "
                f"CV: {r['coefficient_of_variation']} | "
                f"Interval: {r['mean_interval_seconds']}s | "
                f"Connections: {r['connection_count']} | "
                f"Assessment: {r['assessment']}"
            )

        # Write CSV output
        with open(args.output, "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
        print(f"\n[*] Results written to {args.output}")
    else:
        print("[*] No beaconing patterns detected above threshold.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
