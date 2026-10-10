# MITRE ATT&CK Detection Coverage Matrix

## Overview

Maps all custom detections built across Phases 4–6 against the MITRE ATT&CK framework.  
Coverage status: **Detected** (custom rule exists and validated) | **Partial** (rule exists, not fully tested) | **Gap** (no detection)

## Coverage Map

### Credential Access (TA0006)

| Technique | ID | Detection Rule | Tool | Status |
|---|---|---|---|---|
| Brute Force | T1110 | `brute_force_to_success.spl`, Wazuh 100004 | Splunk, Wazuh | _pending_ |
| Credential Stuffing | T1110.004 | `credential_stuffing.yml` (Sigma) | Splunk | _pending_ |

### Execution (TA0002)

| Technique | ID | Detection Rule | Tool | Status |
|---|---|---|---|---|
| PowerShell | T1059.001 | `suspicious_powershell.yml`, Wazuh 100003 | Splunk, Wazuh | _pending_ |

### Persistence (TA0003)

| Technique | ID | Detection Rule | Tool | Status |
|---|---|---|---|---|
| Scheduled Task | T1053.005 | Wazuh 100005 | Wazuh | _pending_ |
| Registry Run Keys | T1547.001 | Wazuh 100002 | Wazuh | _pending_ |
| Create/Modify System Process | T1543.003 | Wazuh 100001 | Wazuh | _pending_ |

### Lateral Movement (TA0008)

| Technique | ID | Detection Rule | Tool | Status |
|---|---|---|---|---|
| SMB/Admin Shares (PsExec) | T1021.002 | `lateral_movement_psexec.spl` | Splunk | _pending_ |

### Command and Control (TA0011)

| Technique | ID | Detection Rule | Tool | Status |
|---|---|---|---|---|
| HTTP C2 Beaconing | T1071.001 | `custom_c2_detection.rules` SID 9000001-9000003 | Suricata | _pending_ |
| DNS Tunneling | T1071.004 | `dns_tunneling.rules` SID 9000010-9000012 | Suricata | _pending_ |
| Encrypted Channel | T1573.002 | `custom_c2_detection.rules` SID 9000003 | Suricata | _pending_ |

### Defence Evasion (TA0005)

| Technique | ID | Detection Rule | Tool | Status |
|---|---|---|---|---|
| Signed Binary Proxy Execution | T1218.005 / T1218.010 | LOLBins hunt queries | Splunk | _pending_ |

## Coverage Summary

| Category | Detected | Partial | Gap | Total |
|---|---|---|---|---|
| Credential Access | | | | |
| Execution | | | | |
| Persistence | | | | |
| Lateral Movement | | | | |
| Command & Control | | | | |
| Defence Evasion | | | | |
| **Total** | | | | |

## ATT&CK Navigator Layer

_Export the completed matrix as an ATT&CK Navigator JSON layer for visual representation._  
_File: `navigator_layer.json` (to be generated)_
