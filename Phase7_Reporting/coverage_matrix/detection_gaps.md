# Detection Gap Analysis & Remediation Plan

## Purpose

Document MITRE ATT&CK techniques that are **not covered** by the current detection stack and propose a remediation roadmap.

## Identified Gaps

### High Priority (Common attack techniques with no detection)

| Technique | ID | Tactic | Gap Reason | Remediation |
|---|---|---|---|---|
| _To be populated after coverage matrix assessment_ | | | | |

### Medium Priority (Less common but impactful)

| Technique | ID | Tactic | Gap Reason | Remediation |
|---|---|---|---|---|
| | | | | |

### Low Priority (Requires additional data sources)

| Technique | ID | Tactic | Missing Data Source | Cost/Effort |
|---|---|---|---|---|
| | | | | |

## Remediation Roadmap

### Quick Wins (Can implement with existing data sources)

| Priority | Technique | Action | Estimated Effort | Target Date |
|---|---|---|---|---|
| 1 | | Write Sigma rule + convert | 2 hours | |
| 2 | | Add Wazuh custom rule | 3 hours | |
| 3 | | Create Splunk correlation search | 4 hours | |

### Requires New Data Sources

| Technique | Required Data Source | Tool/Config Change | Estimated Effort |
|---|---|---|---|
| | Cloud audit logs | Azure AD / Entra ID connector | |
| | Email metadata | Email gateway log forwarding | |

### Requires New Tooling

| Technique | Required Tool | Justification | Cost |
|---|---|---|---|
| | | | |

## Coverage Improvement Tracking

| Date | Techniques Added | New Coverage % | Notes |
|---|---|---|---|
| | | | |
