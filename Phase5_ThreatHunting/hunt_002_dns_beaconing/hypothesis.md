# Hunt 002 — DNS Beaconing Detection

## Hypothesis

**A compromised host is maintaining regular-interval DNS callbacks to an external command-and-control server.** C2 frameworks (Cobalt Strike, DNS-over-HTTPS tunnels) often use DNS for covert communication, producing statistically regular connection patterns that differ from normal browsing behaviour.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Command and Control | Application Layer Protocol: DNS | T1071.004 |
| Command and Control | Non-Standard Port | T1571 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |

## Data Sources

- **Primary:** Zeek conn.log — connection metadata (duration, bytes, interval)
- **Secondary:** Zeek dns.log — query names, types, response codes
- **Enrichment:** Splunk correlation with host-based events from same source IP

## Detection Method

1. Parse Zeek conn.log for all outbound connections per source IP
2. Group connections by destination IP
3. Calculate inter-connection interval statistics (mean, standard deviation, coefficient of variation)
4. Flag destination IPs where the coefficient of variation is very low (< 0.1) — indicating regular-interval beaconing
5. Cross-reference flagged IPs with threat intelligence (MISP, VirusTotal)

## Success Criteria

- Identify any hosts making regular-interval connections to external IPs
- Calculate beaconing scores based on interval regularity
- Distinguish legitimate regular traffic (NTP, update checks) from suspicious beaconing
- Correlate network findings with host-based telemetry

## Scope

- Time range: Last 7 days of Zeek logs
- Network: All monitored subnets
- Exclusions: Known NTP servers, DNS resolvers, OS update endpoints
