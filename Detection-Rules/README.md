# Detection Rules

Custom detection content developed during the internship.

## Wazuh Rules (`wazuh/`)
Custom XML rules and decoders for host-based detection.
- Custom alert rules for specific MITRE ATT&CK techniques
- Decoder scripts for log normalization
- Sysmon-based detection rules

## Suricata Rules (`suricata/`)
Custom `.rules` files for network-based detection.
- Signatures for lateral movement detection
- C2 callback detection rules
- Data exfiltration indicators

## Sigma Rules (`sigma/`)
Vendor-agnostic detection rules in YAML format.
- Can be converted to Splunk SPL, Wazuh, or other SIEM formats
- Tested with Atomic Red Team simulations

## Testing Methodology
All rules tested against:
1. Atomic Red Team attack simulations
2. Known-good traffic baselines
3. False positive validation (< 5% threshold)
