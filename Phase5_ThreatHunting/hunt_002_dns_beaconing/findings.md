# Hunt 002 — DNS Beaconing: Findings

## Hunt Metadata

| Field | Value |
|---|---|
| **Hunt ID** | HUNT-002 |
| **Date** | YYYY-MM-DD |
| **Analyst** | Vignesh R |
| **Duration** | _pending_ |
| **Status** | Not Started |

## Summary

_To be completed after running `zeek_analysis.py` against Zeek conn.log data._

## Beaconing Analysis Results

### Suspicious Pairs (CV < 0.1)

| Source IP | Dest IP | Score | CV | Mean Interval | Connections | Assessment |
|---|---|---|---|---|---|---|
| | | | | | | |

### Benign Regular Traffic (Whitelisted)

| Source IP | Dest IP | Service | Reason for Whitelist |
|---|---|---|---|
| | | NTP | Known NTP server |
| | | DNS | Configured DNS resolver |
| | | Updates | OS update endpoint |

## Cross-Reference

### VirusTotal Lookup
| IP | VT Score | Associated Campaigns |
|---|---|---|
| | | |

### MISP Correlation
| IP | MISP Event | Threat Actor |
|---|---|---|
| | | |

## Outcome

- [ ] True positive — detection rule created
- [ ] True positive — escalated to incident
- [ ] False positive — tuning applied
- [ ] No findings — hypothesis disproven

## Detection Rules Created

_Link to any Suricata or Splunk rules added as a result._

## Recommendations

_Observations on network baseline, additional data sources needed, beaconing threshold tuning._
