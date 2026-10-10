# Phase 5 — Threat Hunting & Purple Team Exercises

**Timeline:** Months 7–8  
**Prerequisite:** Phase 4 complete  
**Focus:** Transition from reactive alert monitoring to proactive, hypothesis-driven threat hunting with purple team validation.

## Objectives

- Develop threat hunting hypotheses grounded in MITRE ATT&CK
- Write Splunk SPL hunting queries and document the full hunt cycle
- Use Zeek logs to hunt for network-level anomalies (beaconing, tunneling)
- Execute attack simulations with Atomic Red Team to validate detection coverage
- Document the complete hunt lifecycle: hypothesis, data source, query, findings, outcome

## Directory Structure

```
Phase5_ThreatHunting/
├── hunt_001_lolbins_persistence/
│   ├── hypothesis.md                    # Hunt hypothesis and MITRE mapping
│   ├── splunk_queries.spl               # SPL queries used during the hunt
│   ├── findings.md                      # Results, IOCs, benign/suspicious classification
│   └── evidence_screenshots/            # Tool output screenshots
├── hunt_002_dns_beaconing/
│   ├── hypothesis.md                    # DNS beaconing hunt hypothesis
│   ├── zeek_analysis.py                 # Python script analysing conn.log for regular-interval connections
│   ├── conn_log_sample.csv              # Sanitised sample data
│   └── findings.md                      # Analysis results
├── atomic_red_team_tests/
│   ├── T1053_scheduled_task.md          # Test execution and detection validation
│   ├── T1059_powershell_execution.md    # PowerShell technique test results
│   └── detection_gap_analysis.md        # Coverage gaps identified across all tests
└── README.md
```

## Hunt Methodology

Each hunt follows the structured cycle:

1. **Hypothesis** — What are we looking for and why? (MITRE ATT&CK grounded)
2. **Data Sources** — Which logs and telemetry feed the hunt?
3. **Query Development** — SPL, Zeek scripts, or Python analysis
4. **Execution** — Run queries, examine results, pivot as needed
5. **Findings** — What was discovered? Benign vs suspicious classification
6. **Outcome** — Detection rule created, escalated, tuning applied, or hypothesis disproven
7. **Documentation** — Full write-up with evidence and MITRE mapping

## Key Activities

### Hunt 001 — LOLBins Persistence
- `Phase5_Task1_Activity1_LOLBinsHunt` — Hypothesis: attackers using Living-off-the-Land binaries (schtasks.exe, mshta.exe, certutil.exe, regsvr32.exe) for persistence
- Data source: Wazuh/Sysmon process creation logs in Splunk
- Hunt for anomalous execution of LOLBins by non-admin users

### Hunt 002 — DNS Beaconing
- `Phase5_Task1_Activity2_DNSBeaconingHunt` — Hypothesis: compromised host maintaining regular-interval DNS callbacks to external C2
- Data source: Zeek dns.log and conn.log
- Python script to detect statistical regularity in connection intervals

### Atomic Red Team Testing
- `Phase5_Task2_Activity1_AtomicTests` — Execute MITRE ATT&CK techniques using Atomic Red Team
- Validate Phase 4 detection rules catch simulated attacks
- Document detection gaps and create improvement backlog

## Tools

- **Splunk** — SPL hunting queries against Windows/Sysmon logs
- **Zeek** — conn.log, dns.log, http.log analysis for network-level hunting
- **Atomic Red Team** — Open-source attack simulation (by Red Canary)
- **Python 3** — Statistical analysis of log data, beaconing detection scripts
- **MITRE ATT&CK Navigator** — Visual coverage mapping
