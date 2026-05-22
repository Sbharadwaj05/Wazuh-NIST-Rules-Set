# Detection Rule Catalog

This catalog details the behavior, required telemetry, and tuning thresholds for the 15 rules provided in the NIST CSF v2.0 Wazuh Pack.

---

## 🔐 Identity & Access Control (Protect)

### 100018: SSH Brute Force (5+ Failures)
* **NIST Mapping**: DE.CM-01
* **MITRE ATT&CK**: T1110.001 (Password Guessing)
* **Description**: Detects 5 or more failed SSH login attempts from the same source IP within a 60-second window.
* **Required Telemetry**: Linux `sshd` logs (via `/var/log/auth.log`).
* **Threshold Tuning**: Modify `<frequency>5</frequency>` and `<timeframe>60</timeframe>` in the XML configuration depending on the exposure of your host.

### 100011: Windows Logon Spray
* **NIST Mapping**: DE.AE-02, DE.CM-03
* **MITRE ATT&CK**: T1110.003 (Password Spraying)
* **Description**: Detects 5 or more failed Windows Logon attempts (Event ID 4625) from the same source IP across multiple accounts within 300 seconds.
* **Required Telemetry**: Windows Security Event Log (EventChannel JSON format).
* **Threshold Tuning**: Adjust `<frequency>5</frequency>` and `<timeframe>300</timeframe>`.

### 100002: Sudo Privilege Escalation (Interactive Shell)
* **NIST Mapping**: PR.AA-05, DE.CM-03
* **MITRE ATT&CK**: T1548.003 (Sudo Abuse)
* **Description**: Detects when a user successfully executes a command to spawn an interactive root shell (`/bin/bash`, `su`) using `sudo`. Avoids generic `sudo` commands to prevent alert fatigue.
* **Required Telemetry**: Linux `sudo` logs (via `/var/log/auth.log`).

### 100003: New User Account Created
* **NIST Mapping**: PR.AA-01, DE.CM-03
* **MITRE ATT&CK**: T1136.001 (Local Account)
* **Description**: Detects the execution of `useradd` or equivalent commands to provision a new local account.
* **Required Telemetry**: Linux system logs (via `/var/log/auth.log` or `syslog`).

---

## 📂 Data Security & Integrity (Protect & Detect)

### 100006: Sensitive File Read (Passwd/Shadow)
* **NIST Mapping**: PR.DS-01, DE.CM-03
* **MITRE ATT&CK**: T1003.008 (Credential Dumping)
* **Description**: Detects read access to highly sensitive authentication files (`/etc/passwd`, `/etc/shadow`).
* **Required Telemetry**: Linux `auditd` logs (`-w /etc/shadow -p r`).

### 100014: Sensitive Permission Change
* **NIST Mapping**: PR.DS-01, PR.AA-05
* **MITRE ATT&CK**: T1222.002 (Linux Permissions)
* **Description**: Detects when a user runs `chmod` or `chown` to alter file permissions recursively or systematically.
* **Required Telemetry**: Linux `auditd` logs.

### 100008: Large File Exfiltration
* **NIST Mapping**: DE.AE-03, PR.DS-02
* **MITRE ATT&CK**: T1030 (Data Transfer Size Limits)
* **Description**: Detects HTTP POST/PUT uploads via a proxy where the bytes sent exceed 100,000,000 (100MB).
* **Required Telemetry**: Proxy syslog (e.g., Squid) with a `proxy:` program name header.
* **Threshold Tuning**: Modify the regex `[0-9]{9,}` to alter the byte threshold (e.g., `{10,}` for 1GB+).

### 100009: Windows Audit Log Cleared
* **NIST Mapping**: DE.CM-09, RS.MA-02
* **MITRE ATT&CK**: T1070.001 (Clear Windows Event Logs)
* **Description**: Detects when the Windows Security Log is explicitly cleared (Event ID 1102).
* **Required Telemetry**: Windows Security Event Log (EventChannel JSON format).

---

## 🦠 Execution & Persistence (Detect)

### 100007: Web Shell Indicators
* **NIST Mapping**: DE.AE-02, RS.MA-02
* **MITRE ATT&CK**: T1505.003 (Web Shell)
* **Description**: Detects anomalous GET/POST requests targeting common web shell scripts (`cmd.php`, `shell.jsp`, `b374k`).
* **Required Telemetry**: Apache or Nginx `access.log`.

### 100004: Cron Job Modification
* **NIST Mapping**: DE.CM-09, PR.DS-01
* **MITRE ATT&CK**: T1053.003 (Cron)
* **Description**: Detects write modifications to cron spool files or directories.
* **Required Telemetry**: Linux `auditd` logs (`-w /etc/cron.d/ -p wa`).

### 100015: Service Install After-Hours
* **NIST Mapping**: DE.CM-09, DE.AE-03
* **MITRE ATT&CK**: T1543.003 (Windows Service)
* **Description**: Detects the installation of a new Windows service (Event ID 7045) outside standard business hours (6 PM - 6 AM or on Weekends).
* **Required Telemetry**: Windows System Event Log.
* **Threshold Tuning**: Adjust the `<time>` or `<weekday>` tags in the rule to align with corporate hours.

### 100012: Process Injection
* **NIST Mapping**: DE.AE-02, RS.AN-08
* **MITRE ATT&CK**: T1055 (Process Injection)
* **Description**: Detects Cross-Process Injection techniques by looking for Sysmon Event ID 8 (`CreateRemoteThread`).
* **Required Telemetry**: Microsoft Sysmon Operational Log.

---

## 📡 Network & Command and Control (Detect)

### 100013: DNS Query to C2 Domain
* **NIST Mapping**: ID.RA-03, DE.CM-01
* **MITRE ATT&CK**: T1071.004 (DNS C2)
* **Description**: Evaluates outbound DNS queries against a CDB list of known malicious Command & Control (C2) domains.
* **Required Telemetry**: Microsoft Sysmon Operational Log (Event ID 22).
* **List Tuning**: Update the `lists/c2-domains` file to add or remove C2 domains. Compilation is automatic on manager restart.

### 100010: PSExec Lateral Movement
* **NIST Mapping**: DE.CM-01, DE.AE-02
* **MITRE ATT&CK**: T1021.002 (SMB/Windows Admin Shares)
* **Description**: Detects PSExec lateral movement by tracking explicit Windows shares access to `IPC$` combined with known named pipes.
* **Required Telemetry**: Windows Security Event Log (Event ID 5145).

### 100005: Outbound Rare Port Egress
* **NIST Mapping**: DE.CM-01, DE.AE-03
* **MITRE ATT&CK**: T1048 (Exfiltration Over Alternative Protocol)
* **Description**: Matches outbound firewall drops or accepts on obscure non-standard ports listed in the `rare-ports` CDB list (e.g., 6667 IRC, 4444 Metasploit).
* **Required Telemetry**: Linux Kernel/`iptables` logs.
* **List Tuning**: Update the `lists/rare-ports` file to define non-standard ports specific to your environment.
