# Phase 7 — Reporting, Metrics Dashboard & Programme Wrap-up

**Timeline:** Months 11–12  
**Prerequisite:** Phases 4–6 complete  
**Focus:** Build operational reporting, demonstrate programme-wide competence, and deliver a complete portfolio.

## Objectives

- Build a Grafana dashboard visualising SOC operational metrics from Wazuh/Splunk data
- Write 3 comprehensive incident reports from the best investigations across the 12-month programme
- Create a MITRE ATT&CK detection coverage matrix mapping custom detections to techniques
- Write a programme review with lessons learned and SOC improvement recommendations

## Directory Structure

```
Phase7_Reporting/
├── grafana_dashboard/
│   ├── dashboard_export.json            # Importable Grafana dashboard definition
│   ├── screenshots/                     # Dashboard screenshots for portfolio
│   └── README.md                        # Dashboard panel descriptions and data sources
├── incident_reports/
│   ├── IR_001_credential_stuffing_campaign.md    # Full IR write-up
│   ├── IR_002_malware_delivery_via_macro.md      # Full IR write-up
│   └── IR_003_insider_threat_data_exfil.md       # Full IR write-up
├── coverage_matrix/
│   ├── mitre_attack_coverage.md         # Detection technique coverage map
│   └── detection_gaps.md                # Identified gaps and remediation plan
└── programme_review/
    └── lessons_learned.md               # End-of-programme review document
```

## Key Activities

### Grafana Dashboard
- `Phase7_Task1_Activity1_GrafanaDashboard`
- **Panels:**
  - Alert volume by severity over time (line chart)
  - MTTA tracking against 15-minute threshold (gauge + trend)
  - False positive rate trending (line chart with 5% target line)
  - Top 10 triggered detection rules (bar chart)
  - Top attacker IPs / targeted assets (table)

### Incident Reports
- `Phase7_Task2_Activity1_IncidentReports`
- Select 3 best investigations from the full 12-month programme
- Each report includes: executive summary, timeline, evidence chain, root cause analysis, MITRE ATT&CK mapping, IOC table, remediation recommendations, and lessons learned

### Coverage Matrix
- `Phase7_Task3_Activity1_CoverageMatrix`
- Map all custom detections (Phase 4) against MITRE ATT&CK
- Identify techniques with detection coverage vs gaps
- Export ATT&CK Navigator layer for visual representation

### Programme Review
- `Phase7_Task4_Activity1_LessonsLearned`
- SOC tooling evaluation — what worked, what didn't
- Process improvements recommended
- Skills developed and competency demonstration
- Future development roadmap

## Tools

- **Grafana** — Dashboard creation and visualisation
- **Splunk / Wazuh** — Data sources for metrics
- **MITRE ATT&CK Navigator** — Coverage matrix visualisation
