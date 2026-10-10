# Phase 4 — Detection Engineering & Content Development

**Timeline:** Months 5–6  
**Prerequisite:** Phase 3 complete  
**Focus:** Transition from triaging alerts to writing the detection rules that generate them.

## Objectives

- Write custom Splunk correlation searches (multi-event logic with time windows)
- Build custom Wazuh rules in XML for host-based threat detection
- Author Suricata rules for network-based threat signatures
- Create Sigma rules and convert to Splunk SPL / Wazuh format using `sigma-cli`
- Document every detection with MITRE ATT&CK mapping, logic explanation, false-positive guidance, and tuning recommendations

## Directory Structure

```
Phase4_Detection/
├── splunk_correlation_searches/
│   ├── brute_force_to_success.spl        # 5+ failed logins → success from same IP within 10 min
│   ├── lateral_movement_psexec.spl       # PsExec-based lateral movement detection
│   └── README.md                         # Logic explanation per rule
├── wazuh_custom_rules/
│   ├── local_rules.xml                   # Custom /var/ossec/etc/rules/local_rules.xml entries
│   └── testing_results.md                # Rule testing and validation results
├── suricata_rules/
│   ├── custom_c2_detection.rules         # C2 beaconing pattern detection
│   └── dns_tunneling.rules               # DNS tunneling signatures
└── sigma_rules/
    ├── credential_stuffing.yml           # Credential stuffing detection
    └── suspicious_powershell.yml         # Suspicious PowerShell execution patterns
```

## Detection Documentation Format

Each detection rule must include:

| Field | Description |
|---|---|
| **Rule Name** | Descriptive name following naming convention |
| **Detection Logic** | What the rule triggers on (conditions, thresholds, time windows) |
| **MITRE ATT&CK** | Tactic, Technique, Sub-technique ID |
| **Data Sources** | Required log sources and fields |
| **False Positives** | Known benign triggers and how to distinguish them |
| **Tuning Recommendations** | Threshold adjustments, exclusion lists |
| **Severity** | Critical / High / Medium / Low |
| **Testing** | Validation method (Atomic Red Team test ID if applicable) |

## Key Activities

### Splunk Correlation Searches
- `Phase4_Task1_Activity1_BruteForceCorrelation` — Multi-event search: failed auth → successful login from same source within time window
- `Phase4_Task1_Activity2_LateralMovementDetection` — PsExec / WMI / remote service creation correlation

### Wazuh Custom Rules
- `Phase4_Task2_Activity1_PrivEscDetection` — Privilege escalation attempt detection (suspicious service installations, registry modifications)
- `Phase4_Task2_Activity2_RuleTesting` — Rule validation with expected vs actual alert output

### Suricata Network Rules
- `Phase4_Task3_Activity1_C2Beaconing` — Periodic callback patterns to external infrastructure
- `Phase4_Task3_Activity2_DNSTunneling` — Unusually long DNS queries, high-frequency lookups to single domain

### Sigma Rules
- `Phase4_Task4_Activity1_CredentialStuffing` — Universal detection format, converted to Splunk SPL and Wazuh XML
- `Phase4_Task4_Activity2_SuspiciousPowerShell` — Encoded commands, download cradles, AMSI bypass patterns

## Tools

- **Splunk** — Correlation searches, saved searches with alerting
- **Wazuh** — Custom XML rules in `local_rules.xml`, rule testing with `ossec-logtest`
- **Suricata** — Custom `.rules` files, rule reload with `suricatasc`
- **sigma-cli** — Sigma rule conversion to target SIEM formats
- **Atomic Red Team** — Validation of detection coverage
