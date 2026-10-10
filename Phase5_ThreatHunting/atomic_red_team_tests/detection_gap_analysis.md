# Detection Gap Analysis

## Purpose

Track which MITRE ATT&CK techniques tested via Atomic Red Team were detected vs missed by the current detection stack (Splunk, Wazuh, Suricata).

## Coverage Summary

| Technique | ID | Splunk | Wazuh | Suricata | Overall |
|---|---|---|---|---|---|
| Scheduled Task | T1053.005 | _pending_ | _pending_ | N/A | _pending_ |
| PowerShell Execution | T1059.001 | _pending_ | _pending_ | N/A | _pending_ |
| _Add more as tested_ | | | | | |

## Gap Categories

### Fully Detected (All relevant tools alerted)
| Technique ID | Tools | Notes |
|---|---|---|
| | | |

### Partially Detected (Some tools alerted)
| Technique ID | Detected By | Missed By | Reason |
|---|---|---|---|
| | | | |

### Not Detected (No alerts triggered)
| Technique ID | Expected Data Source | Gap Reason | Remediation Plan |
|---|---|---|---|
| | | | |

## Remediation Backlog

| Priority | Technique ID | Gap | Action Required | Status |
|---|---|---|---|---|
| HIGH | | | Write new detection rule | [ ] Done |
| MEDIUM | | | Tune existing rule threshold | [ ] Done |
| LOW | | | Add new data source | [ ] Done |

## MITRE ATT&CK Navigator Layer

_Export ATT&CK Navigator layer JSON showing coverage vs gaps._  
_File: `mitre_navigator_layer.json` (to be generated after all tests complete)_

## Observations

_Key takeaways from purple team testing — systemic gaps, data source limitations, tooling recommendations._
