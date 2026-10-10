# Atomic Red Team Test — T1059.001: PowerShell Execution

## Test Overview

| Field | Value |
|---|---|
| **Technique** | T1059.001 — Command and Scripting Interpreter: PowerShell |
| **Tactic** | Execution |
| **Test Date** | YYYY-MM-DD |
| **Platform** | Windows 10 (Lab VM) |
| **Atomic Test** | [Atomic Red Team T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) |

## Pre-Test Checklist

- [ ] Sysmon running and logging to Splunk
- [ ] Wazuh agent active on target host
- [ ] Phase4 Sigma rules deployed (suspicious_powershell.yml)
- [ ] Baseline alerts documented

## Test Execution

### Atomic Test #1 — Encoded PowerShell Command
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1
```

### Atomic Test #2 — PowerShell Download Cradle
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 2
```

### Expected Behaviour
- PowerShell process creation with `-EncodedCommand` parameter
- Download cradle with `Net.WebClient.DownloadString`
- Wazuh Rule 100003 should trigger
- Sigma rule `suspicious_powershell.yml` conversion should match

## Detection Results

### Splunk
| Detection Rule | Triggered? | Alert Details |
|---|---|---|
| Sigma: suspicious_powershell (SPL) | [ ] Yes / [ ] No | |
| Sysmon Process Creation | [ ] Yes / [ ] No | |

### Wazuh
| Rule ID | Triggered? | Alert Level |
|---|---|---|
| 100003 | [ ] Yes / [ ] No | |

### Suricata
| Rule SID | Triggered? | Notes |
|---|---|---|
| N/A (host-based) or network callback | | |

## Gap Analysis

| Gap | Description | Remediation |
|---|---|---|
| | | |

## Cleanup
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1,2 -Cleanup
```
