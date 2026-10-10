# Atomic Red Team Test — T1053.005: Scheduled Task

## Test Overview

| Field | Value |
|---|---|
| **Technique** | T1053.005 — Scheduled Task/Job: Scheduled Task |
| **Tactic** | Persistence, Privilege Escalation, Execution |
| **Test Date** | YYYY-MM-DD |
| **Platform** | Windows 10 (Lab VM) |
| **Atomic Test** | [Atomic Red Team T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) |

## Pre-Test Checklist

- [ ] Sysmon running and logging to Splunk
- [ ] Wazuh agent active on target host
- [ ] Suricata monitoring network interface
- [ ] Baseline alerts documented

## Test Execution

### Atomic Test #1 — Scheduled Task Startup Script
```powershell
# Command executed on Windows lab VM
Invoke-AtomicTest T1053.005 -TestNumbers 1
```

### Expected Behaviour
- schtasks.exe process creation (Sysmon EventID 1)
- Windows EventID 4698 (Scheduled task created)
- Wazuh Rule 100005 should trigger

## Detection Results

### Splunk
| Detection Rule | Triggered? | Alert Details |
|---|---|---|
| Sysmon Process Creation | [ ] Yes / [ ] No | |
| Phase4 Correlation Search | [ ] Yes / [ ] No | |

### Wazuh
| Rule ID | Triggered? | Alert Level |
|---|---|---|
| 100005 | [ ] Yes / [ ] No | |

### Suricata
| Rule SID | Triggered? | Notes |
|---|---|---|
| N/A (host-based technique) | N/A | |

## Gap Analysis

| Gap | Description | Remediation |
|---|---|---|
| | | |

## Cleanup
```powershell
# Remove test artifacts
Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup
```
