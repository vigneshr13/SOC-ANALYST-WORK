# Phase 6 — Automation & SOAR Playbook Development

**Timeline:** Months 9–10  
**Prerequisite:** Phase 5 complete  
**Focus:** Build automated security response workflows using Shuffle SOAR and Python enrichment scripts.

## Objectives

- Build SOAR playbooks using Shuffle (open-source alternative to Cortex XSOAR / Splunk SOAR)
- Automate phishing email triage, malware alert enrichment, and brute-force response
- Write Python enrichment scripts calling free APIs (VirusTotal, AbuseIPDB, URLScan.io)
- Document each playbook with flowcharts, trigger conditions, step-by-step logic, and manual review points
- Integrate playbooks with TheHive for automated case creation

## Directory Structure

```
Phase6_SOAR/
├── playbook_phishing_triage/
│   ├── workflow_diagram.md              # Flowchart of the automated workflow
│   ├── shuffle_export.json              # Exported Shuffle workflow definition
│   ├── vt_enrichment.py                 # VirusTotal URL/hash enrichment script
│   └── README.md                        # Playbook documentation
├── playbook_brute_force_response/
│   ├── workflow_diagram.md              # Flowchart of auto-block workflow
│   ├── pfsense_block_script.py          # Auto-block source IP in pfSense
│   └── README.md                        # Playbook documentation
├── enrichment_scripts/
│   ├── virustotal_lookup.py             # VirusTotal API integration
│   ├── abuseipdb_check.py               # AbuseIPDB reputation check
│   └── urlscan_submit.py                # URLScan.io submission and result retrieval
└── README.md
```

## Playbook Documentation Format

Each playbook must include:

| Field | Description |
|---|---|
| **Playbook Name** | Descriptive name |
| **Trigger** | What initiates the workflow (alert type, threshold, manual) |
| **Input** | Data the playbook receives (alert fields, IOCs) |
| **Steps** | Numbered sequence with tool/API at each step |
| **Decision Points** | Where manual analyst review is required |
| **Output** | TheHive case, block action, notification |
| **MITRE ATT&CK** | Relevant technique(s) this playbook responds to |
| **SLA** | Expected execution time and response window |

## Key Activities

### Phishing Email Triage Playbook
- `Phase6_Task1_Activity1_PhishingPlaybook`
- **Trigger:** Email reported as suspicious
- **Workflow:** Extract URLs/attachments → VirusTotal check → sender reputation via AbuseIPDB → auto-classify → create TheHive case

### Brute Force Response Playbook
- `Phase6_Task1_Activity2_BruteForcePlaybook`
- **Trigger:** Splunk alert on 10+ failed logins from single source
- **Workflow:** Alert fires → extract source IP → auto-block in pfSense → create TheHive case → webhook notification

### Enrichment Scripts
- `Phase6_Task2_Activity1_EnrichmentScripts`
- Python scripts for VirusTotal, AbuseIPDB, and URLScan.io API integration
- Each script designed for standalone use and Shuffle integration

## Tools

- **Shuffle SOAR** — Workflow orchestration and automation
- **TheHive** — Case management and incident tracking
- **pfSense** — Firewall rule automation for IP blocking
- **VirusTotal API** — File hash and URL reputation
- **AbuseIPDB API** — IP address abuse reporting and lookup
- **URLScan.io API** — URL scanning and analysis
- **Python 3** — Enrichment scripts and API integration
