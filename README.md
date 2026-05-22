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

## 📊 Mapped Detection Rules (15 Active Detections + 2 Base Rules)

This pack provides coverage across **Identify (ID)**, **Protect (PR)**, **Detect (DE)**, and **Respond (RS)** functions of the NIST CSF:

| Rule ID | Name | NIST CSF v2.0 Mappings | MITRE ATT&CK | Source Data |
| :--- | :--- | :--- | :--- | :--- |
| **100017** | SSH Auth Failure (base) | DE.CM-01 | — | Linux `sshd` |
| **100018** | SSH Brute Force (5+ in 60s) | DE.CM-01, RS.MA-02 | T1110.001 (Password Guessing) | Linux `sshd` |
| **100002** | Sudo Privilege Escalation | PR.AA-05, DE.CM-03 | T1548.003 (Sudo Abuse) | Linux `sudo` |
| **100003** | New User Account Created | PR.AA-01, DE.CM-03 | T1136.001 (Local Account) | Linux `useradd` |
| **100004** | Cron Job Modification | DE.CM-09, PR.DS-01 | T1053.003 (Cron Job) | Linux `auditd` |
| **100005** | Outbound Rare Port Egress | DE.CM-01, DE.AE-03 | T1048 (Alternative Protocol) | Linux `iptables` |
| **100006** | Sensitive File Read | PR.DS-01, DE.CM-03 | T1003.008 (Cred Dumping) | Linux `auditd` |
| **100007** | Web Shell Indicators | DE.AE-02, RS.MA-02 | T1505.003 (Web Shell) | Apache/Nginx |
| **100008** | Large File Exfiltration | DE.AE-03, PR.DS-02 | T1030 (Data Transfer Limit) | Proxy/Web Logs |
| **100009** | Windows Audit Log Cleared | DE.CM-09, RS.MA-02 | T1070.001 (Clear Event Logs) | Win Security |
| **100010** | PSExec Lateral Movement | DE.CM-01, DE.AE-02 | T1021.002 (SMB Shares) | Win EventChannel |
| **100016** | Windows logon failure (base) | DE.AE-02 | — | Win EventChannel |
| **100011** | Windows Logon Spray (5+ in 300s) | DE.AE-02, DE.CM-03 | T1110.003 (Password Spraying)| Win EventChannel |
| **100012** | Process Injection | DE.AE-02, RS.AN-08 | T1055 (Process Injection) | Win Sysmon |
| **100013** | DNS Query to C2 Domain | ID.RA-03, DE.CM-01 | T1071.004 (DNS C2) | Win Sysmon |
| **100014** | Sensitive Permission Change | PR.DS-01, PR.AA-05 | T1222.002 (Linux Permissions)| Linux `auditd` |
| **100015** | Service Install After-Hours | DE.CM-09, DE.AE-03 | T1543.003 (Windows Service)  | Win EventChannel |

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
