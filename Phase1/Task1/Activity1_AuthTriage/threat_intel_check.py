#!/usr/bin/env python3
"""
Phase1_Task1_Activity1 — Threat Intel Cross-Reference
Checks attacker IPs against OTX AlienVault (MISP substitute)
"""
import requests
import csv
import json

OTX_API_KEY = "fakekey"

def check_ip_otx(ip):
    """Check IP against OTX AlienVault threat intel feed."""
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        data = resp.json()
        pulse_count = data.get('pulse_info', {}).get('count', 0)
        country = data.get('country_name', 'Unknown')
        return {
            'ip': ip,
            'pulse_count': pulse_count,
            'known_malicious': pulse_count > 0,
            'country': country,
            'reputation': data.get('reputation', 0)
        }
    except Exception as e:
        return {
            'ip': ip,
            'pulse_count': 0,
            'known_malicious': False,
            'country': 'Error',
            'reputation': 0,
            'error': str(e)
        }

def main():
    # IPs from the brute-force triage
    attacker_ips = ['10.10.10.30']

    results = []
    for ip in attacker_ips:
        print(f"Checking {ip}...")
        result = check_ip_otx(ip)
        results.append(result)
        print(f"  Pulses: {result['pulse_count']}")
        print(f"  Known malicious: {result['known_malicious']}")
        print(f"  Country: {result['country']}")

    # Save results
    with open('threat_intel_results.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['ip', 'pulse_count', 'known_malicious', 'country', 'reputation'])
        writer.writeheader()
        writer.writerows(results)

    # Save full JSON response for evidence
    with open('threat_intel_results.json', 'w') as f:
        json.dump(results, f, indent=2)

    print("\nResults saved to threat_intel_results.csv and threat_intel_results.json")
    print("\nNote: 10.10.10.30 is a private IP (lab environment),")
    print("so OTX will not have threat data on it.")
    print("In a real SOC, the attacker IP would be a public IP")
    print("and this check would return actual threat intel.")

if __name__ == '__main__':
    main()