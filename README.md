# Wazuh NIST CSF v2.0 Detection Rule Pack

[![Wazuh Version](https://img.shields.io/badge/Wazuh-%3E%3D4.8.0-blue.svg)](https://wazuh.com)
[![NIST CSF Mapping](https://img.shields.io/badge/NIST%20CSF-v2.0-orange.svg)](https://www.nist.gov/cyberframework)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

An open-source, production-grade knowledge base and detection pack mapping custom Wazuh rules to **NIST Cybersecurity Framework (CSF) v2.0** outcomes.

### 💡 Why this exists
Wazuh includes compliance mappings internally, but operationalizing NIST-aligned detections across custom environments can often feel fragmented. This project provides structured, modular Wazuh detection rules for easier **compliance visibility**, **monitoring support**, and **detection engineering experimentation**. We do not claim to provide "complete NIST implementation," but rather a rigorously tested foundation for detection-alignment.

---

## 🏗️ Architecture & Workflow

``mermaid
graph LR
    A[Endpoint Telemetry] -->|Sysmon / Auditd| B[Wazuh Agent]
    B -->|Log Stream| C[Wazuh Manager]
    C -->|Custom Decoders| D[Rules Engine]
    D -->|NIST/MITRE Mapping| E[Security Alert]
    E --> F[Dashboard / SIEM]
`

## 🧪 Lab Tested Environment
To ensure production readiness and high-fidelity alerts, all rules have been actively tested against:
* **OS**: Ubuntu 22.04 LTS & Windows Server 2022
* **Wazuh**: Manager & Agent v4.8.0
* **Telemetry**: Sysmon (Windows), Auditd & Syslog (Linux)
* **Simulation**: Custom synthetic log injection and wazuh-logtest harness

## 🔥 Example Alert Output
Every alert triggered by this pack is natively enriched with MITRE ATT&CK context and NIST CSF tags directly in the Wazuh JSON event:
``json
{
  "rule": {
    "level": 10,
    "description": "SSH brute force attack detected from a single source IP",
    "id": "100018",
    "mitre": {
      "id": [ "T1110.001" ],
      "tactic": [ "Credential Access" ],
      "technique": [ "Brute Force: Password Guessing" ]
    },
    "groups": [ "authentication_failures", "brute_force", "nist_de.cm-01", "nist_rs.ma-02" ]
  },
  "decoder": { "name": "sshd" }
}
`

---

## ?? Project Mission & Core Principles

1. **Rigorous Evidence-Driven Mapping:** We map rules only where there is explicit, telemetry-supported alignment to a NIST CSF v2.0 subcategory. We never overclaim compliance.
2. **Traceability & Auditing:** Every mapping is fully documented inside the rule XML files and verified using repeatable synthetic log tests.
3. **Standalone Rule Design:** All rules are designed to be self-sufficient, preventing fragile cascading rule dependencies and making them easy to port.

---

## 📂 Repository Structure

- `rules/` — Custom Wazuh rule XML files organized by NIST CSF Function and Category.
- `lists/` — Source files for CDB lists (e.g., threat intel domains, rare egress ports).
- `tests/` — Automated test harness and high-fidelity synthetic log sets (`trigger.log` and `benign.log`).
- `mappings/` — Machine-readable JSON mappings correlating rules to NIST and MITRE ATT&CK.
- `docs/` — Deployment and testing guides, along with the master NIST Mapping Table.

---

## 📊 Mapped Detection Rules (50 Active Detections)

This pack provides coverage across **Identify (ID)**, **Protect (PR)**, **Detect (DE)**, and **Respond (RS)** functions of the NIST CSF:

### Coverage Heatmap
| NIST Function | Subcategories Covered | Active Rules |
|---|---|---|
| **ID - Identify** | ID.RA-03 | 1 |
| **PR - Protect** | PR.AA-01, PR.AA-05, PR.DS-01 | 11 |
| **DE - Detect** | DE.AE-02, DE.AE-03, DE.CM-01, DE.CM-03, DE.CM-09 | 36 |
| **GV - Govern** | GV.PO-01 | 1 |
| **RC - Recover** | RC.RP-01 | 1 |

### Detailed Rule Mapping

| Rule ID | NIST CSF v2.0 | MITRE ATT&CK | Alert Description | Telemetry Source | Severity |
|---------|---------------|---------------|-------------------|------------------|----------|
| 100002 | PR.AA-05, DE.CM-03 | T1548.003 (Abuse Elevation Control Mechanism: Sudo and Sudo Caching) | Sudo Privilege Escalation | sudo | Medium |
| 100003 | PR.AA-01, DE.CM-03 | T1136.001 (Create Account: Local Account) | New User Account Created | syslog | Medium |
| 100004 | DE.CM-09, PR.DS-01 | T1053.003 (Scheduled Task/Job: Cron) | Cron Job Modification | auditd | Medium |
| 100005 | DE.CM-01, DE.AE-03 | T1048 (Exfiltration Over Alternative Protocol) | Outbound Connection to Monitored Port | iptables | Medium |
| 100006 | PR.DS-01, DE.CM-03 | T1003.008 (OS Credential Dumping: /etc/passwd and /etc/shadow) | Sensitive File Read (/etc/passwd or /etc/shadow) | auditd | High |
| 100007 | DE.AE-02, RS.MA-02 | T1505.003 (Server Software Component: Web Shell) | Web Shell Indicators in HTTP Requests | apache/nginx | High |
| 100008 | DE.AE-03, PR.DS-02 | T1030 (Data Transfer Size Limits) | Large File Exfiltration (>=100MB) | proxy/web | Medium |
| 100009 | DE.CM-09, RS.MA-02 | T1070.001 (Indicator Removal: Clear Windows Event Logs) | Windows Audit Log Cleared | windows_eventchannel | High |
| 100010 | DE.CM-01, DE.AE-02 | T1021.002 (Remote Services: SMB/Windows Admin Shares) | PSExec Lateral Movement | windows_eventchannel | High |
| 100011 | DE.AE-02, DE.CM-03 | T1110.003 (Brute Force: Password Spraying) | Repeated Authentication Failures (Multiple Accounts) | windows_eventchannel | Medium |
| 100012 | DE.AE-02, RS.AN-08 | T1055 (Process Injection) | Process Injection Indicator (Sysmon) | windows_eventchannel | High |
| 100013 | ID.RA-03, DE.CM-01 | T1071.004 (Application Layer Protocol: DNS) | DNS Query to Known C2 Domain | windows_eventchannel | High |
| 100014 | PR.DS-01, PR.AA-05 | T1222.002 (File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification) | Sensitive File Permission Change | auditd | Medium |
| 100015 | DE.CM-09, DE.AE-03 | T1543.003 (Create or Modify System Process: Windows Service) | Service Installed Outside Business Hours | windows_eventchannel | Medium |
| 100018 | DE.CM-01, RS.MA-02 | T1110.001 (Brute Force: Password Guessing) | SSH Brute Force Detection | syslog | High |
| 100019 | PR.DS-01, DE.CM-09 | T1098 (Account Manipulation) | /etc/passwd Modified | auditd | High |
| 100020 | PR.DS-01, DE.CM-09 | T1003.008 (OS Credential Dumping: /etc/shadow) | /etc/shadow Modified | auditd | Critical |
| 100021 | PR.AA-05, DE.CM-09 | T1098.004 (Account Manipulation: SSH Authorized Keys) | SSH authorized_keys Modified | auditd | High |
| 100022 | PR.AA-05, DE.AE-02 | T1548.001 (Abuse Elevation Control Mechanism: Setuid and Setgid) | SUID/SGID Bit Set on Binary | auditd | High |
| 100023 | DE.CM-09, DE.AE-02 | T1547.006 (Boot or Logon Autostart Execution: Kernel Modules and Extensions) | Kernel Module Loaded | syslog | High |
| 100024 | DE.CM-09, RS.MA-02 | T1070.002 (Indicator Removal on Host: Clear Linux or Mac System Logs) | Log File Deleted or Truncated | auditd | High |
| 100025 | DE.AE-02, DE.CM-03 | T1059 (Command and Scripting Interpreter) | Execution from /tmp or /dev/shm | auditd | Medium |
| 100026 | DE.CM-09, PR.DS-01 | T1053.003 (Scheduled Task/Job: Cron) | Root Crontab Modification | auditd | Critical |
| 100027 | DE.AE-02, DE.CM-03 | T1059.001 (PowerShell) | PowerShell Encoded Command | windows_sysmon | High |
| 100028 | DE.AE-02, RS.MA-02 | T1059.001 (PowerShell) | PowerShell Download Cradle | windows_sysmon | High |
| 100029 | DE.CM-09, DE.AE-02 | T1053.005 (Scheduled Task) | Schtasks Creation | windows_security | Medium |
| 100030 | DE.CM-09, PR.DS-01 | T1547.001 (Registry Run Keys) | Registry Run Key Modification | windows_sysmon | High |
| 100031 | DE.AE-02, RS.MA-02 | T1490 (Inhibit System Recovery) | Volume Shadow Copy Deleted | windows_security | Critical |
| 100032 | PR.AA-01, DE.CM-03 | T1136.001 (Local Account) | New Local Admin Account | windows_security | High |
| 100033 | PR.AA-05, DE.CM-09 | T1021.001 (Remote Desktop Protocol) | RDP Enabled via Registry | windows_sysmon | High |
| 100034 | DE.CM-09, DE.AE-02 | T1546.003 (WMI Event Subscription) | WMI Event Subscription | windows_sysmon | High |
| 100035 | DE.AE-02, PR.AA-05 | T1003.001 (LSASS Memory) | LSASS Memory Access | windows_sysmon | High |
| 100036 | DE.AE-02, RS.MA-02 | T1003 (OS Credential Dumping) | Mimikatz Indicators | windows_sysmon | Critical |
| 100037 | DE.AE-02, DE.CM-01 | T1550.002 (Pass the Hash) | Pass-the-Hash Indicators | windows_security | High |
| 100038 | DE.AE-02, ID.RA-03 | T1003.006 (DCSync) | DCSync Attack | windows_security | Critical |
| 100039 | DE.AE-02, ID.RA-03 | T1558.003 (Kerberoasting) | Kerberoasting Indicators | windows_security | High |
| 100040 | DE.AE-02, DE.CM-03 | T1110 (Brute Force) | Multiple Account Lockouts | windows_security | Medium |
| 100041 | PR.AA-05, DE.CM-03 | T1003.008 (/etc/passwd and /etc/shadow) | Linux Passwd Accessed by Non-Root | auditd | Medium |
| 100042 | DE.AE-02, RS.MA-02 | T1059.004 (Unix Shell) | Reverse Shell Spawned | auditd | High |
| 100043 | DE.AE-02, DE.CM-03 | T1027 (Obfuscated Files or Information) | Base64 Encoded Command | auditd | Medium |
| 100044 | DE.CM-01, DE.AE-03 | T1071.004 (DNS) | DNS Tunneling Indicators | windows_sysmon | High |
| 100045 | DE.CM-01, DE.AE-03 | T1090.003 (Multi-hop Proxy: TOR) | TOR Exit Node Connection | iptables | High |
| 100046 | DE.AE-02, DE.CM-01 | T1071.001 (Web Protocols) | Beaconing Behaviour | windows_sysmon | Medium |
| 100047 | DE.AE-02, DE.CM-03 | T1105 (Ingress Tool Transfer) | Certutil Used to Download File | windows_sysmon | High |
| 100048 | DE.AE-02, DE.CM-03 | T1218 (Signed Binary Proxy Execution) | Regsvr32 Executing Remote Script | windows_sysmon | High |
| 100049 | GV.PO-01, DE.CM-03 | T1078 (Valid Accounts) | Admin Account Used Outside Business Hours | windows_security | Medium |
| 100050 | RC.RP-01, DE.CM-09 | T1490 (Inhibit System Recovery) | Backup Process Failure | syslog | High |
| 100051 | DE.CM-09, RS.MA-02 | T1070.001 (Indicator Removal: Clear Windows Event Logs) | Sysmon Event Log Cleared | windows_eventchannel | High |
| 100052 | DE.AE-02, PR.DS-01 | T1562.001 (Impair Defenses: Disable or Modify Tools) | Windows Defender Tampering via PowerShell | windows_sysmon | Critical |
| 100053 | DE.CM-03, DE.AE-02 | T1036 (Masquerading) | Execution from Recycle Bin | windows_sysmon | High |

---

## 🚀 Quick Start

### 1. Deployment
To deploy this rule pack on your Wazuh Manager:
1. Clone this repository to your Wazuh manager or copy the files.
2. Follow the detailed steps in the [Deployment Guide](docs/deployment-guide.md) to install rules, configure CDB lists in `ossec.conf`, and compile the lists.
3. Restart the Wazuh manager:
   ```bash
   sudo systemctl restart wazuh-manager
   ```

### 2. Automated Validation
This repository includes a testing harness designed to run positive (trigger) and negative (benign) assertions for every rule using `wazuh-logtest`:
```bash
./tests/test-runner.sh
```

---

## 📚 Extensive Documentation

To help SOC analysts, detection engineers, and IT administrators properly deploy and maintain this ruleset, we have thoroughly documented the required system configurations, rule internals, and troubleshooting lessons learned:

1. **[Agent Configuration & Prerequisites](docs/prerequisites.md)**: Essential guide on how to configure Windows (Audit Policy, Sysmon, EventChannels) and Linux (`auditd`, `iptables`, `syslog`) endpoints to generate the telemetry required by these rules.
2. **[Detection Rule Catalog](docs/rule-catalog.md)**: A detailed breakdown of all 50 active rules, including the specific logs they evaluate, MITRE mappings, and threshold tuning instructions.
3. **[Troubleshooting & Lessons Learned](docs/troubleshooting.md)**: A deep-dive masterclass into Wazuh's rules engine quirks (e.g., decoder shadowing, JSON parsing differences, level 0 invisible correlation). Read this if you plan to modify or extend the rules!
4. **[Deployment Architecture](docs/deployment-guide.md)**: How to install the rules, lists, and custom decoders on your Wazuh manager.

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding new mappings, updating threat intelligence feeds, or submitting new rules.

## 📄 License
This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
