# Wazuh NIST CSF v2.0 Detection Rule Pack

[![Wazuh Version](https://img.shields.io/badge/Wazuh-%3E%3D4.8.0-blue.svg)](https://wazuh.com)
[![NIST CSF Mapping](https://img.shields.io/badge/NIST%20CSF-v2.0-orange.svg)](https://www.nist.gov/cyberframework)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

An open-source, production-grade knowledge base and detection pack mapping custom Wazuh rules to **NIST Cybersecurity Framework (CSF) v2.0** outcomes. Designed for detection engineers, SOC analysts, and security auditors who need rigorous, evidence-driven, and test-backed mappings.

---

## 🎯 Project Mission & Core Principles

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

## 📊 Mapped Detection Rules (23 Active Detections + 2 Base Rules)

This pack provides coverage across **Identify (ID)**, **Protect (PR)**, **Detect (DE)**, and **Respond (RS)** functions of the NIST CSF:

### Coverage Heatmap
| NIST Function | Subcategories Covered | Active Rules |
|---|---|---|
| **ID — Identify** | ID.RA-03 | 1 |
| **PR — Protect** | PR.AA-01, PR.AA-05, PR.DS-01, PR.DS-02 | 7 |
| **DE — Detect** | DE.CM-01, DE.CM-03, DE.CM-09, DE.AE-02, DE.AE-03 | 13 |
| **RS — Respond** | RS.MA-02, RS.AN-08 | 2 |

### Detailed Rule Mapping

| Rule ID | NIST CSF v2.0 | MITRE ATT&CK | Alert Description | Telemetry Source | Severity |
|---------|---------------|---------------|-------------------|------------------|----------|
| `100018` | DE.CM-01 | T1110.001 | SSH Brute Force (5+ Failures) | Linux `sshd` | High |
| `100011` | DE.AE-02, DE.CM-03 | T1110.003 | Windows Logon Spray (Multi-Account) | Win Security (4625) | Medium |
| `100002` | PR.AA-05, DE.CM-03 | T1548.003 | Sudo Privilege Escalation (Interactive Shell) | Linux `sudo` | Medium |
| `100003` | PR.AA-01, DE.CM-03 | T1136.001 | New User Account Created | Linux `syslog` | Medium |
| `100004` | DE.CM-09, PR.DS-01 | T1053.003 | Cron Job Modification | Linux `auditd` | Medium |
| `100005` | DE.CM-01, DE.AE-03 | T1048 | Outbound Connection to Monitored Port | Linux `iptables` | Medium |
| `100006` | PR.DS-01, DE.CM-03 | T1003.008 | Sensitive File Read (`/etc/shadow`) | Linux `auditd` | High |
| `100007` | DE.AE-02, RS.MA-02 | T1505.003 | Web Shell Indicators in HTTP Requests | Nginx/Apache logs | High |
| `100008` | DE.AE-03, PR.DS-02 | T1030 | Large File Exfiltration (>=100MB) | Proxy Logs | Medium |
| `100009` | DE.CM-09, RS.MA-02 | T1070.001 | Windows Audit Log Cleared (Event 1102) | Win Security | High |
| `100010` | DE.CM-01, DE.AE-02 | T1021.002 | PSExec Lateral Movement | Win Security (5145) | High |
| `100012` | DE.AE-02, RS.AN-08 | T1055 | Process Injection Indicator (Sysmon Event 8) | Win Sysmon | High |
| `100013` | ID.RA-03, DE.CM-01 | T1071.004 | DNS Query to Known C2 Domain | Win Sysmon (22) | High |
| `100014` | PR.DS-01, PR.AA-05 | T1222.002 | Sensitive File Permission Change (`chmod`) | Linux `auditd` | Medium |
| `100015` | DE.CM-09, DE.AE-03 | T1543.003 | Service Installed Outside Business Hours | Win System (7045) | Medium |
| `100019` | PR.DS-01, DE.CM-09 | T1098 | `/etc/passwd` Modified | Linux `auditd` | High |
| `100020` | PR.DS-01, DE.CM-09 | T1003.008 | `/etc/shadow` Modified | Linux `auditd` | Critical |
| `100021` | PR.AA-05, DE.CM-09 | T1098.004 | SSH `authorized_keys` Modified | Linux `auditd` | High |
| `100022` | PR.AA-05, DE.AE-02 | T1548.001 | SUID/SGID Bit Set on Binary | Linux `auditd` | High |
| `100023` | DE.CM-09, DE.AE-02 | T1547.006 | Kernel Module Loaded (`insmod`/`modprobe`) | Linux `syslog` | High |
| `100024` | DE.CM-09, RS.MA-02 | T1070.002 | Log File Deleted or Truncated | Linux `auditd` | High |
| `100025` | DE.AE-02, DE.CM-03 | T1059 | Execution from `/tmp` or `/dev/shm` | Linux `auditd` | Medium |
| `100026` | DE.CM-09, PR.DS-01 | T1053.003 | Root Crontab Modification | Linux `auditd` | Critical |

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
2. **[Detection Rule Catalog](docs/rule-catalog.md)**: A detailed breakdown of all 15 rules, including the specific logs they evaluate, MITRE mappings, and threshold tuning instructions.
3. **[Troubleshooting & Lessons Learned](docs/troubleshooting.md)**: A deep-dive masterclass into Wazuh's rules engine quirks (e.g., decoder shadowing, JSON parsing differences, level 0 invisible correlation). Read this if you plan to modify or extend the rules!
4. **[Deployment Architecture](docs/deployment-guide.md)**: How to install the rules, lists, and custom decoders on your Wazuh manager.

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding new mappings, updating threat intelligence feeds, or submitting new rules.

## 📄 License
This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
