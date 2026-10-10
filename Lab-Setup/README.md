# Lab Environment Setup

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    VMware Hypervisor                      │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  Windows 10   │  │    Ubuntu     │  │    Linux      │  │
│  │              │  │   Server      │  │  (Kali/Other) │  │
│  │  • Sysmon    │  │              │  │              │  │
│  │  • Splunk UF │  │  • Splunk    │  │  • Attack    │  │
│  │              │  │  • Zeek      │  │    tools     │  │
│  │  Target/     │  │  • Suricata  │  │  • Python    │  │
│  │  Endpoint    │  │  • TShark    │  │    scripts   │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────────┘  │
│         │                 │                              │
│         │    Logs via     │                              │
│         │  Splunk UF      │                              │
│         └────────────────►│                              │
│                           │                              │
│              Splunk SIEM ◄┤                              │
│              Dashboard    │◄── Zeek conn.log, dns.log    │
│                           │◄── Suricata eve.json         │
└─────────────────────────────────────────────────────────┘
```

## VM Details

### Windows 10 — Endpoint
- **Role:** Target machine, log source
- **Sysmon:** Configured with SwiftOnSecurity config for process creation, network connections, file creation monitoring
- **Splunk Universal Forwarder:** Forwards Windows Event Logs and Sysmon logs to Splunk on Ubuntu
- **Key log sources:** Security, System, PowerShell, Sysmon (EventIDs 1, 3, 7, 8, 10, 11, 12, 13, 22)

### Ubuntu Server — SIEM & Network Sensor
- **Role:** Central SIEM, network monitoring
- **Splunk:** Receives logs from Windows UF, Zeek, and Suricata
- **Zeek:** Network protocol analysis, generating conn.log, dns.log, http.log, ssl.log, files.log
- **Suricata:** IDS/IPS with ET Open rules, outputting eve.json
- **TShark:** CLI packet analysis for targeted investigations

### Linux (Kali/Additional) — Attack & Analysis
- **Role:** Attack simulation, scripting, analysis workstation

## Configuration Files

Store your tool configs in `configs/`:
- `sysmon_config.xml` — Sysmon configuration
- `inputs.conf` — Splunk UF inputs configuration
- `outputs.conf` — Splunk UF outputs configuration
- `suricata.yaml` — Suricata configuration
- `local.zeek` — Zeek site configuration
- `ossec.conf` — Wazuh agent/manager configuration (when deployed)

## Network Diagrams

Store lab topology diagrams in `network-diagrams/`

## Screenshots

Store setup evidence screenshots in `screenshots/`
