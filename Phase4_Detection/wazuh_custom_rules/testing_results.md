# Wazuh Custom Rule Testing Results

## Testing Methodology

All rules tested using `/var/ossec/bin/ossec-logtest` with sample log lines. Each rule validated for correct triggering, severity level, and MITRE ATT&CK mapping.

## Test Results

### Rule 100001 — Suspicious Service Installation

| Field | Result |
|---|---|
| **Test Date** | YYYY-MM-DD |
| **Input** | Windows EventID 7045 (new service installed) |
| **Expected** | Level 12 alert, T1543.003 mapping |
| **Actual** | _pending_ |
| **Status** | [ ] Pass / [ ] Fail |

### Rule 100002 — Registry Run Key Modification

| Field | Result |
|---|---|
| **Test Date** | YYYY-MM-DD |
| **Input** | Sysmon EventID 13 (registry value set) targeting Run key |
| **Expected** | Level 10 alert, T1547.001 mapping |
| **Actual** | _pending_ |
| **Status** | [ ] Pass / [ ] Fail |

### Rule 100003 — Encoded PowerShell Command

| Field | Result |
|---|---|
| **Test Date** | YYYY-MM-DD |
| **Input** | Sysmon EventID 1 with `-EncodedCommand` parameter |
| **Expected** | Level 12 alert, T1059.001 mapping |
| **Actual** | _pending_ |
| **Status** | [ ] Pass / [ ] Fail |

### Rule 100004 — Brute Force (Multiple Failed Logins)

| Field | Result |
|---|---|
| **Test Date** | YYYY-MM-DD |
| **Input** | 5+ Windows EventID 4625 within 120 seconds |
| **Expected** | Level 10 alert, T1110 mapping |
| **Actual** | _pending_ |
| **Status** | [ ] Pass / [ ] Fail |

### Rule 100005 — Scheduled Task Creation

| Field | Result |
|---|---|
| **Test Date** | YYYY-MM-DD |
| **Input** | Sysmon EventID 1 — schtasks.exe /Create |
| **Expected** | Level 10 alert, T1053.005 mapping |
| **Actual** | _pending_ |
| **Status** | [ ] Pass / [ ] Fail |

## Tuning Log

| Date | Rule ID | Change | Reason |
|---|---|---|---|
| | | | |
