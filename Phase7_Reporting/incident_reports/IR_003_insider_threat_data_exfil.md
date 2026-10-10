# Incident Report: IR-003 — Insider Threat Data Exfiltration

## Executive Summary

| Field | Value |
|---|---|
| **Incident ID** | IR-003 |
| **Date Detected** | YYYY-MM-DD |
| **Date Resolved** | YYYY-MM-DD |
| **Severity** | Critical |
| **Classification** | Insider Threat — Data Exfiltration (Confirmed) |
| **MITRE ATT&CK** | T1567 (Exfiltration Over Web Service), T1041 (Exfiltration Over C2 Channel), T1074.001 (Local Data Staging) |
| **Analyst** | Vignesh R |
| **Status** | _pending_ |

## Detection

- Detection source: Zeek conn.log anomaly (Hunt 002 beaconing analysis) + Splunk data volume alert
- Initial alert time: YYYY-MM-DD HH:MM UTC
- Alert details: _pending_

## Timeline

| Time (UTC) | Event |
|---|---|
| HH:MM | Unusual data upload volume detected |
| HH:MM | Analyst began investigation |
| HH:MM | Source host identified |
| HH:MM | User account correlated |
| HH:MM | Staging directory discovered |
| HH:MM | Account suspended, host isolated |
| HH:MM | Forensic imaging initiated |
| HH:MM | Scope assessment completed |

## Evidence Chain

### IOC Table

| Type | Value | Source | Confidence |
|---|---|---|---|
| User Account | | Windows Security Log | High |
| Upload Destination | | Zeek http.log | High |
| Staging Directory | | Sysmon file creation | High |
| Data Volume | | Zeek conn.log | High |

### Data Flow
```
Sensitive files (file server)
  → Local staging directory (C:\Users\<user>\AppData\Local\Temp\)
    → Compressed archive (.zip)
      → Uploaded to external cloud storage via HTTPS
```

### Network Evidence
_Zeek conn.log showing large outbound HTTPS transfers to cloud storage provider._

## Root Cause Analysis

_Insider motivation, access review findings, DLP policy gaps._

## Impact Assessment

| Category | Impact |
|---|---|
| Data volume exfiltrated | |
| Data classification | |
| Regulatory implications | GDPR / HPRA considerations |
| Business impact | |

## Containment & Remediation

1. **Immediate:** User account suspended, host isolated for forensics
2. **Short-term:** Forensic analysis of staging directory, upload destination subpoena
3. **Long-term:** _DLP policy implementation, USB restrictions, cloud upload monitoring, access review_

## Lessons Learned

| Question | Answer |
|---|---|
| What went well? | |
| What could improve? | |
| Detection gap identified? | |
| Process change recommended? | |

## References

- MITRE ATT&CK: [T1567](https://attack.mitre.org/techniques/T1567/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/)
- Related Phase5 hunt: `hunt_002_dns_beaconing/`
