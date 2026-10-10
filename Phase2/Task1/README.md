# Phase 2 — Automation, Optimization & Compliance

## Task 1: Log Correlation, Zeek Protocol Analysis & Asset Mapping

**Objective:** Transition from basic monitoring to advanced log correlation, deep packet inspection, and infrastructure asset mapping.

---

### Activities

| # | Activity | Deliverable | Format | Tools |
|---|---|---|---|---|
| 1 | Log Correlation and Anomaly Detection | `Phase2_Task1_Activity1_CorrelationAnalysis.sql` | SQL | Wazuh, Python 3, Bash |
| 2 | Zeek Protocol Inspection & Network Traffic Analysis | `Phase2_Task1_Activity2_ZeekProtocol.log` | LOG | Zeek, Wireshark, TShark |

---

### Activity 1: Log Correlation and Anomaly Detection
- Correlate system event logs with firewall drops using SQL join logic
- Match source IPs from firewall logs with unauthorized access attempts
- Define filters to maintain < 5% false positive threshold
- Document methodology for repeatable, audit-ready queries
- Output refined correlation queries and analysis matrix

### Activity 2: Zeek Protocol Inspection
- Ingest PCAP datasets with Zeek, extract metadata
- Target SMB and DNS query anomalies
- Filter with TShark for protocol headers indicating compromise or exfiltration
- Deploy custom Zeek scripts for conn.log session analysis
- Analyze non-standard port traffic
- Baseline normal traffic parameters
- Correlate Zeek telemetry against known IOCs
