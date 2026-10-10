# Incident Report: IR-001 — Credential Stuffing Campaign

## Executive Summary

| Field | Value |
|---|---|
| **Incident ID** | IR-001 |
| **Date Detected** | YYYY-MM-DD |
| **Date Resolved** | YYYY-MM-DD |
| **Severity** | High |
| **Classification** | Credential Stuffing (Confirmed) |
| **MITRE ATT&CK** | T1110.004 (Credential Stuffing) |
| **Analyst** | Vignesh R |
| **Status** | _pending_ |

## Detection

_How was this incident detected? Which alert, rule, or hunt identified it?_

- Detection source: Phase4 Splunk correlation search `brute_force_to_success.spl`
- Initial alert time: YYYY-MM-DD HH:MM UTC
- Alert details: _pending_

## Timeline

| Time (UTC) | Event |
|---|---|
| HH:MM | Initial failed login attempts detected |
| HH:MM | Alert fired in Splunk |
| HH:MM | Analyst acknowledged alert (MTTA: XX min) |
| HH:MM | Investigation began |
| HH:MM | Source IP blocked in pfSense |
| HH:MM | TheHive case created |
| HH:MM | Incident contained |
| HH:MM | Post-incident review completed |

## Evidence Chain

### IOC Table

| Type | Value | Source | Confidence |
|---|---|---|---|
| IP Address | | Splunk alert | High |
| User Accounts | | Windows Security Log | High |
| Geolocation | | AbuseIPDB | Medium |

### Log Evidence

```
# Key Splunk query results — paste sanitised output here
```

### Network Evidence

_Zeek/Suricata findings related to this incident._

## Root Cause Analysis

_What caused this incident? How did the attacker get the credential list? Was there a prior breach?_

## Impact Assessment

| Category | Impact |
|---|---|
| Accounts affected | |
| Successful compromises | |
| Data accessed | |
| Business impact | |

## Containment & Remediation

1. **Immediate:** Source IP blocked in pfSense via SOAR playbook
2. **Short-term:** Affected accounts locked, password resets forced
3. **Long-term:** _Recommendations for MFA, rate limiting, CAPTCHA_

## Lessons Learned

| Question | Answer |
|---|---|
| What went well? | |
| What could improve? | |
| Detection gap identified? | |
| Process change recommended? | |

## References

- MITRE ATT&CK: [T1110.004 — Credential Stuffing](https://attack.mitre.org/techniques/T1110/004/)
- Related Phase4 detection: `brute_force_to_success.spl`
- Related SOAR playbook: `playbook_brute_force_response/`
