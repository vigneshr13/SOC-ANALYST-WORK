#!/usr/bin/env python3
"""
Phase1_Task1_Activity1 : Authentication Anomaly Triage
MITRE ATT&CK: T1110 (Brute Force) / T1110.001 (Password Guessing)
"""
import csv
import hashlib
from collections import Counter
from datetime import datetime

INPUT_FILE = "auth_triage_raw.csv"
OUTPUT_FILE = "Phase1_Task1_Activity1_AuthTriage.csv"

def sha256_mask(value):
    """SHA-256 hash PII per SOC data handling policy."""
    return hashlib.sha256(value.encode()).hexdigest()[:16]

def analyse_auth_logs(input_path, output_path):
    events = []
    with open(input_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append(row)

    # Count failed logins per source IP
    ip_counts = Counter(e.get('src_ip', 'unknown') for e in events)

    print(f"Total failed login events: {len(events)}")
    print(f"Unique source IPs: {len(ip_counts)}")
    print(f"\nTop offenders:")
    for ip, count in ip_counts.most_common(10):
        print(f"  {ip}: {count} failures")

    # Write enriched output with SHA-256 masked usernames
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'timestamp', 'src_ip', 'username_hash', 'logon_type',
            'failure_reason', 'mitre_technique', 'verdict',
            'total_failures_from_ip'
        ])
        for e in events:
            ip = e.get('src_ip', 'unknown')
            username = e.get('TargetUserName', 'unknown')
            count = ip_counts[ip]
            # Flag as brute force if 5+ failures from same IP
            verdict = 'BRUTE_FORCE' if count >= 5 else 'SUSPICIOUS' if count >= 3 else 'BENIGN'
            writer.writerow([
                e.get('_time', ''),
                ip,
                sha256_mask(username),
                e.get('LogonType', ''),
                e.get('FailureReason', ''),
                'T1110.001' if verdict != 'BENIGN' else '',
                verdict,
                count
            ])

    print(f"\nOutput written to {output_path}")

if __name__ == '__main__':
    analyse_auth_logs(INPUT_FILE, OUTPUT_FILE)
