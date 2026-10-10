# Splunk Correlation Searches

Custom saved searches using multi-event correlation logic for advanced threat detection.

## Rules

### brute_force_to_success.spl
- **Detection:** 5+ failed authentication events followed by a successful login from the same source IP within a 10-minute window
- **MITRE ATT&CK:** T1110 — Brute Force (TA0006 Credential Access)
- **Data Source:** Windows Security Event Logs (EventCode 4625, 4624) via Splunk UF
- **False Positives:** Legitimate users mistyping passwords, password managers with cached expired credentials
- **Tuning:** Adjust failed-login threshold and time window per environment baseline

### lateral_movement_psexec.spl
- **Detection:** PsExec service creation on remote hosts correlated with new network logon sessions
- **MITRE ATT&CK:** T1021.002 — Remote Services: SMB/Windows Admin Shares (TA0008 Lateral Movement)
- **Data Source:** Sysmon (EventID 1 process creation, EventID 17/18 pipe events), Windows Security logs
- **False Positives:** IT admin tools using PsExec for legitimate remote management
- **Tuning:** Whitelist known admin workstations and service accounts

## File Format

Each `.spl` file contains:
```
| ---- Rule Metadata ----
| Rule Name: <name>
| MITRE ATT&CK: <technique_id>
| Severity: <level>
| Description: <what it detects>
| ---- Search Logic ----
<SPL query>
```
