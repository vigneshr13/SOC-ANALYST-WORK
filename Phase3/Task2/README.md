# Phase 3 — Advanced Intelligence & Engineering

## Task 2: Threat Intelligence Integration & EDR Policy Tuning

**Objective:** Automate threat intelligence collection via MISP and fine-tune EDR detection policies through simulation testing.

---

### Activities

| # | Activity | Deliverable | Format | Tools |
|---|---|---|---|---|
| 1 | MISP Threat Intelligence Integration | `Phase3_Task2_Activity1_MISPIntegration.py` | PY | MISP, Python 3, STIX/TAXII |
| 2 | EDR Policy Tuning via Simulation | `Phase3_Task2_Activity2_EDRPolicy.xml` | XML | Python 3, EDR Engine, Git |

---

### Activity 1: MISP Threat Intelligence Integration
- Configure automated STIX/TAXII feed ingestion into MISP
- Implement confidence-based IOC filtering (IPs, hashes, domains)
- Develop Python sync scripts using MISP API endpoints
- Establish intelligence aging policies for stale indicator purging
- Measure and document detection efficiency gains

### Activity 2: EDR Policy Tuning
- Analyze policy XML structures for overly broad/noisy rules
- Execute Python-based attack simulations (obfuscated PowerShell, registry writes)
- Verify EDR detection triggers and measure endpoint processing latency
- Adjust policy sensitivity, document edge cases and coverage gaps
- Maintain < 5% false positive target
- Commit version-controlled policy XML to repo
