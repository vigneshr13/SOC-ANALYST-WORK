# Threat Hunting

Proactive threat hunting activities using hypothesis-driven methodology.

## Splunk Queries (`splunk-queries/`)
Saved SPL searches for recurring hunts:
- Authentication anomaly detection
- PowerShell abuse patterns
- Lateral movement indicators
- DNS tunneling detection

## Zeek Scripts (`zeek-scripts/`)
Custom Zeek scripts for network-level hunting:
- Connection anomaly analysis (conn.log)
- DNS query pattern analysis
- Non-standard port usage detection
- Long connection duration analysis

## Hunt Reports (`hunt-reports/`)
Documented hunts following the format:
1. **Hypothesis** — What are we looking for and why
2. **Data Sources** — Which logs/telemetry
3. **Hunt Methodology** — Queries, scripts, steps taken
4. **Findings** — What was discovered
5. **MITRE ATT&CK Mapping** — Relevant techniques
6. **Recommendations** — Detection rules created, gaps identified
