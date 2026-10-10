# Hunt 001 — LOLBins Persistence

## Hypothesis

**An attacker is using Living-off-the-Land binaries (LOLBins) to establish persistence on compromised Windows endpoints.** These binaries are legitimate system tools that bypass application whitelisting and blend in with normal system activity.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | LOLBin |
|---|---|---|---|
| Persistence | Scheduled Task/Job | T1053.005 | schtasks.exe |
| Execution | Signed Binary Proxy Execution | T1218.005 | mshta.exe |
| Defence Evasion | Ingress Tool Transfer | T1105 | certutil.exe |
| Defence Evasion | Signed Binary Proxy Execution | T1218.010 | regsvr32.exe |
| Execution | Command and Scripting Interpreter | T1059.003 | cmd.exe (via unusual parent) |

## Data Sources

- **Primary:** Sysmon EventID 1 (Process Creation) via Splunk
- **Secondary:** Wazuh process monitoring alerts
- **Enrichment:** Sysmon EventID 3 (Network Connection) for LOLBins making outbound connections

## Success Criteria

- Identify any LOLBin execution by non-administrative users
- Detect LOLBins launched from unusual parent processes (e.g. Office applications spawning certutil.exe)
- Flag LOLBins making outbound network connections (certutil downloading remote payloads)
- Differentiate legitimate IT admin usage from suspicious patterns

## Scope

- Time range: Last 30 days of Sysmon logs
- Endpoints: All Windows machines forwarding to Splunk via Universal Forwarder
- Exclusions: Known IT admin accounts (document in findings)
