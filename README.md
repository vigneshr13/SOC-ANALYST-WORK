# SOC Analyst  Operations

Structured SOC Analyst programme covering triage, detection engineering, threat hunting, SOAR automation, and operational reporting in a virtualized enterprise environment.

## Programme Timeline

| Phase | Focus | Months | Status |
|---|---|---|---|
| **Phase 1** | Foundational Triage & Visibility | 1–2 | [ ] |
| **Phase 2** | Automation, Optimization & Compliance | 2–3 | [ ] |
| **Phase 3** | Advanced Intelligence & Engineering | 3–4 | [ ] |
| **Phase 4** | Detection Engineering & Content Development | 5–6 | [ ] |
| **Phase 5** | Threat Hunting & Purple Team Exercises | 7–8 | [ ] |
| **Phase 6** | SOAR Playbook Development & Automation | 9–10 | [ ] |
| **Phase 7** | Reporting, Metrics & Programme Wrap-up | 11–12 | [ ] |

## Lab Environment

| VM | OS | Role | Key Tools |
|---|---|---|---|
| **Windows 10** | Windows 10 | Endpoint / Target | Sysmon, Splunk Universal Forwarder |
| **Ubuntu Server** | Ubuntu | SIEM / Network Sensor | Splunk, Zeek, Suricata, TShark |
| **Linux (Kali/Additional)** | Linux | Attack / Analysis | Offensive tools, scripting |

**SIEM Architecture:** Windows endpoint → Sysmon + Splunk UF → Splunk (Ubuntu) ← Zeek/Suricata network telemetry

## Repository Structure

```
├── Phase1/                              # Months 1–2: Foundational Triage & Visibility
│   └── Task1/                           # Alert triage, log analysis, MITRE mapping
│       ├── Activity1_AuthTriage.csv
│       ├── Activity2_PSForensics.html
│       ├── Activity3_NetworkAnomaly.txt
│       ├── Activity4_PhishingTriage.xlsx
│       ├── Activity5_VulnScan.csv
│       └── Activity6_ShiftHandover.pdf
│
├── Phase2/                              # Months 2–3: Automation & Compliance
│   ├── Task1/                           # Log correlation, Zeek protocol analysis
│   └── Task2/                           # Vulnerability scanning, EDR tuning
│
├── Phase3/                              # Months 3–4: Advanced Intelligence
│   ├── Task1/                           # Incident response, TheHive
│   ├── Task2/                           # MISP integration, EDR policy
│   └── Task3/                           # IAM audit, compliance, stakeholder briefing
│
├── Phase4_Detection/                    # Months 5–6: Detection Engineering
│   ├── splunk_correlation_searches/     # Multi-event SPL correlation rules
│   ├── wazuh_custom_rules/              # Custom XML rules for local_rules.xml
│   ├── suricata_rules/                  # Network-based threat signatures
│   └── sigma_rules/                     # Universal detection format (YAML)
│
├── Phase5_ThreatHunting/                # Months 7–8: Proactive Hunting
│   ├── hunt_001_lolbins_persistence/    # LOLBins persistence hunt
│   ├── hunt_002_dns_beaconing/          # DNS beaconing detection (Python + Zeek)
│   └── atomic_red_team_tests/           # ATT&CK technique validation
│
├── Phase6_SOAR/                         # Months 9–10: Automation & Orchestration
│   ├── playbook_phishing_triage/        # Automated phishing email triage
│   ├── playbook_brute_force_response/   # Auto-block brute force sources
│   └── enrichment_scripts/              # VT, AbuseIPDB, URLScan.io integrations
│
├── Phase7_Reporting/                    # Months 11–12: Metrics & Review
│   ├── grafana_dashboard/               # SOC operational metrics dashboard
│   ├── incident_reports/                # 3 comprehensive IR write-ups
│   ├── coverage_matrix/                 # MITRE ATT&CK detection mapping
│   └── programme_review/                # Lessons learned & future roadmap
│
├── Detection-Rules/                     # Reference: Wazuh, Suricata, Sigma rules
├── Threat-Hunting/                      # Reference: SPL queries, Zeek scripts, reports
├── SOAR-Automation/                     # Reference: Shuffle playbooks, Python scripts
├── Investigation-Reports/               # Full incident write-ups
├── Evidence/                            # pcaps, logs, screenshots
├── Enterprise-Tools/                    # Qualys, Microsoft 365, CrowdStrike
├── Lab-Setup/                           # Environment documentation
├── Templates/                           # Reusable report templates
└── Scripts/                             # Utility scripts
```

## Operational Metrics (KPI Targets)

| Metric | Target | Description |
|---|---|---|
| MTTA | ≤ 15 minutes | Mean Time to Acknowledge for high-severity alerts |
| False Positive Rate | < 5% | Signal-to-noise optimization across IDS/EDR |
| Concurrent Cases | Max 3 | Active investigation workload ceiling |
| Data Privacy | SHA-256 hashing | PII masking in all transit, storage, and reporting |
| Threat Intel SLA | Real-time STIX/TAXII | Automated ingestion with confidence filtering |

## Tools & Technologies

**SIEM & Log Management:** Splunk, Wazuh  
**Network Security:** Zeek, Suricata, TShark, Wireshark, pfSense  
**Threat Intelligence:** MISP (STIX/TAXII feeds)  
**Incident Response:** TheHive, Cortex  
**Vulnerability Management:** OpenVAS, Qualys  
**SOAR:** Shuffle  
**Endpoint Detection:** Sysmon, CrowdStrike  
**Cloud Security:** Microsoft 365 (Entra ID, Defender, Sentinel, Purview)  
**Dashboarding:** Grafana  
**Testing:** Atomic Red Team  
**Scripting & Automation:** Python 3, Bash, SQL, KQL  
**Compliance Frameworks:** ISO 27001, GDPR, MITRE ATT&CK  

## Naming Convention

All deliverables follow: `Phase{n}_Task{n}_Activity{n}_ShortDescription.ext`

## Progress Tracker

### Months 1–4:  Core SOC
- [ ] **Phase 1** — Foundational Triage & Visibility
  - [ ] Task 1: Alert triage, log analysis, phishing assessment, vulnerability scanning
- [ ] **Phase 2** — Automation, Optimization & Compliance
  - [ ] Task 1: Log correlation, Zeek protocol analysis
  - [ ] Task 2: OpenVAS scanning, EDR tuning
- [ ] **Phase 3** — Advanced Intelligence & Engineering
  - [ ] Task 1: Incident response with TheHive
  - [ ] Task 2: MISP integration, EDR policy tuning
  - [ ] Task 3: IAM audit, compliance reporting, remediation, stakeholder briefing

### Months 5–6: Detection Engineering
- [ ] **Phase 4** — Detection Engineering & Content Development
  - [ ] Splunk correlation searches (brute force, lateral movement)
  - [ ] Wazuh custom rules (priv esc, persistence, PowerShell)
  - [ ] Suricata rules (C2 beaconing, DNS tunneling)
  - [ ] Sigma rules (credential stuffing, suspicious PowerShell)

### Months 7–8: Threat Hunting
- [ ] **Phase 5** — Threat Hunting & Purple Team Exercises
  - [ ] Hunt 001: LOLBins persistence
  - [ ] Hunt 002: DNS beaconing detection
  - [ ] Atomic Red Team validation tests
  - [ ] Detection gap analysis

### Months 9–10: SOAR Automation
- [ ] **Phase 6** — SOAR Playbook Development
  - [ ] Phishing email triage playbook (Shuffle)
  - [ ] Brute force auto-response playbook
  - [ ] Enrichment scripts (VirusTotal, AbuseIPDB, URLScan.io)

### Months 11–12: Reporting & Review
- [ ] **Phase 7** — Reporting, Metrics & Programme Wrap-up
  - [ ] Grafana SOC metrics dashboard
  - [ ] 3 comprehensive incident reports
  - [ ] MITRE ATT&CK coverage matrix
  - [ ] Programme review & lessons learned
