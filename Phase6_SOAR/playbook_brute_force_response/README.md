# Playbook: Brute Force Auto-Response

## Overview

| Field | Value |
|---|---|
| **Playbook Name** | Automated Brute Force Response |
| **MITRE ATT&CK** | T1110 (Brute Force) |
| **Trigger** | Splunk alert: 10+ failed logins from single source IP |
| **SOAR Platform** | Shuffle |
| **Response SLA** | Auto-block within 2 minutes of alert |

## Workflow Steps

1. **Receive Alert** — Splunk sends webhook to Shuffle on brute-force detection
2. **Extract Source IP** — Parse alert payload for offending IP address
3. **Reputation Check** — Query AbuseIPDB for IP reputation and abuse history
4. **Block Decision** — If external IP with abuse score > 50: auto-block; else: analyst review
5. **Block in pfSense** — Execute API call to add IP to pfSense block list
6. **Create Case** — Open TheHive case with alert details and block action log
7. **Notify** — Webhook notification to SOC channel with case link

## Decision Points (Manual Review Required)

- Internal IP source: never auto-block, escalate for investigation
- AbuseIPDB score < 50: analyst reviews before blocking (possible legitimate user)
- VPN or load-balancer IPs: whitelist check before any block action

## Files

- `workflow_diagram.md` — Visual flowchart
- `pfsense_block_script.py` — Python script to add/remove pfSense firewall rules via API
