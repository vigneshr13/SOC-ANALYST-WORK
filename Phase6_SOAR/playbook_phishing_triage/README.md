# Playbook: Phishing Email Triage

## Overview

| Field | Value |
|---|---|
| **Playbook Name** | Automated Phishing Email Triage |
| **MITRE ATT&CK** | T1566.001 (Phishing: Spearphishing Attachment), T1566.002 (Phishing: Spearphishing Link) |
| **Trigger** | Email reported as suspicious by user or detected by email gateway |
| **SOAR Platform** | Shuffle |
| **Response SLA** | Initial classification within 5 minutes |

## Workflow Steps

1. **Receive Alert** — Shuffle webhook receives phishing report
2. **Extract IOCs** — Parse email for sender address, URLs, attachment hashes
3. **Check URLs** — Submit each URL to VirusTotal API for reputation scoring
4. **Check Sender** — Query AbuseIPDB for sender IP reputation
5. **Check Attachments** — Submit file hashes to VirusTotal for malware analysis
6. **Classify Threat** — Auto-classify based on enrichment results:
   - All clean → Low risk, auto-close
   - 1+ suspicious indicator → Medium risk, analyst review
   - Known malicious → High risk, escalate immediately
7. **Create Case** — Open TheHive case with all enrichment data attached
8. **Notify** — Webhook notification to SOC channel

## Decision Points (Manual Review Required)

- Medium-risk classification: analyst confirms or reclassifies before action
- URLs with borderline VT scores (1-3 detections): manual analysis recommended
- Zero-day indicators: no VT data available, manual sandbox analysis needed

## Files

- `workflow_diagram.md` — Visual flowchart of the workflow
- `shuffle_export.json` — Importable Shuffle workflow definition
- `vt_enrichment.py` — VirusTotal enrichment script used in the workflow
