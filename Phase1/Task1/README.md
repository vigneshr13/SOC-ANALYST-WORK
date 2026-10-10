# Phase 1 — Foundational Triage & Visibility

## Task 1: SOC Foundational Triage and Incident Response Integration

**Objective:** Establish baseline proficiency in alert triage, log analysis, and incident response within an enterprise SOC environment.

**Operational Constraints:**
- MTTA ≤ 15 minutes
- False positive rate < 5%
- Max 3 concurrent open cases
- SHA-256 hashing for all PII

---

### Activities

| # | Activity | Deliverable | Format | Tools |
|---|---|---|---|---|
| 1 | Log-Based Authentication Anomaly Triage | `Phase1_Task1_Activity1_AuthTriage.csv` | CSV | Wazuh, Python 3, MISP, TheHive |
| 2 | PowerShell Execution Forensics | `Phase1_Task1_Activity2_PSForensics.html` | HTML | Wireshark, TShark, VirtualBox, Bash |
| 3 | Network Traffic Anomaly Visualization | `Phase1_Task1_Activity3_NetworkAnomaly.txt` | TXT | Suricata, Zeek, Wireshark |
| 4 | Phishing Email Threat Assessment | `Phase1_Task1_Activity4_PhishingTriage.xlsx` | XLSX | MISP, Python 3 |
| 5 | Vulnerability Assessment Correlation | `Phase1_Task1_Activity5_VulnScan.csv` | CSV | OpenVAS, TheHive, Python 3 |
| 6 | Shift Handover & Compliance Documentation | `Phase1_Task1_Activity6_ShiftHandover.pdf` | PDF | Git |

---

### Activity 1: Log-Based Authentication Anomaly Triage
- Analyze `wazuh_auth_brute_force_events.log` for brute-force attempts
- Extract source IPs, timestamps, correlate with expected auth patterns
- Map anomalous requests to MITRE ATT&CK (Credential Access — T1110)
- Parse logs with Python 3, apply dynamic data masking (SHA-256) to usernames/IPs
- Cross-reference IPs against MISP threat intel feeds
- Escalate confirmed malicious IPs in TheHive

### Activity 2: PowerShell Execution Forensics
- Analyze `windows_event_log_powershell_execution.log`
- Isolate malicious script blocks bypassing execution policies
- Decode base64-encoded payloads, map to MITRE ATT&CK (Execution — T1059.001)
- Use TShark for associated network C2 callback analysis
- Document de-obfuscation process with command-line arguments and parent PID

### Activity 3: Network Traffic Anomaly Visualization
- Identify beaconing behavior in Suricata/Zeek traffic data
- Filter with BPF syntax for source/destination metadata
- Determine protocol (HTTP/S vs tunnelled/non-standard ports)
- Document in SOC daily standup briefing format
- Justify false-positive dismissals with protocol headers

### Activity 4: Phishing Email Threat Assessment
- Categorize phishing emails: sender reputation, URL analysis, attachment integrity
- Extract IOCs from email headers/body, cross-reference with MISP
- Inspect MIME structure for hidden payloads
- Apply SHA-256 masking to recipient PII
- Score risk and recommend domain-level blocking

### Activity 5: Vulnerability Assessment Correlation
- Configure and execute OpenVAS scan
- Cross-reference vulnerabilities with active incident logs
- Prioritize using CVSS scoring and asset criticality
- Generate remediation summaries (CVE, affected version, hardening steps)
- Link findings to TheHive case management

### Activity 6: Shift Handover & Compliance Documentation
- Synthesize all shift actions into handover brief
- Follow SOC_Incident_Response_Playbook_v2.docx standards
- Summarize unresolved issues, pending analysis, ongoing monitoring
- Document tool limitations and process improvement feedback
