# Detection Rule Catalog

This catalog contains detailed documentation for the 50 rules provided in the NIST CSF v2.0 Wazuh Pack.

Each entry includes:
- The base telemetry required to trigger the rule
- Any thresholds or frequencies for correlation rules
- The primary NIST CSF mapping
- The primary MITRE ATT&CK mapping

---

## 🔐 Complete Rule Breakdown (100002 - 100053)

### Rule 100002: Sudo Privilege Escalation
* **NIST Mapping**: PR.AA-05, DE.CM-03
* **MITRE ATT&CK**: T1548.003 (Abuse Elevation Control Mechanism: Sudo and Sudo Caching)
* **Description**: Detailed detection for sudo privilege escalation.
* **Required Telemetry**: sudo logs.

### Rule 100003: New User Account Created
* **NIST Mapping**: PR.AA-01, DE.CM-03
* **MITRE ATT&CK**: T1136.001 (Create Account: Local Account)
* **Description**: Detailed detection for new user account created.
* **Required Telemetry**: syslog logs.

### Rule 100004: Cron Job Modification
* **NIST Mapping**: DE.CM-09, PR.DS-01
* **MITRE ATT&CK**: T1053.003 (Scheduled Task/Job: Cron)
* **Description**: Detailed detection for cron job modification.
* **Required Telemetry**: auditd logs.

### Rule 100005: Outbound Connection to Monitored Port
* **NIST Mapping**: DE.CM-01, DE.AE-03
* **MITRE ATT&CK**: T1048 (Exfiltration Over Alternative Protocol)
* **Description**: Detailed detection for outbound connection to monitored port.
* **Required Telemetry**: iptables logs.

### Rule 100006: Sensitive File Read (/etc/passwd or /etc/shadow)
* **NIST Mapping**: PR.DS-01, DE.CM-03
* **MITRE ATT&CK**: T1003.008 (OS Credential Dumping: /etc/passwd and /etc/shadow)
* **Description**: Detailed detection for sensitive file read (/etc/passwd or /etc/shadow).
* **Required Telemetry**: auditd logs.

### Rule 100007: Web Shell Indicators in HTTP Requests
* **NIST Mapping**: DE.AE-02, RS.MA-02
* **MITRE ATT&CK**: T1505.003 (Server Software Component: Web Shell)
* **Description**: Detailed detection for web shell indicators in http requests.
* **Required Telemetry**: apache/nginx logs.

### Rule 100008: Large File Exfiltration (>=100MB)
* **NIST Mapping**: DE.AE-03, PR.DS-02
* **MITRE ATT&CK**: T1030 (Data Transfer Size Limits)
* **Description**: Detailed detection for large file exfiltration (>=100mb).
* **Required Telemetry**: proxy/web logs.

### Rule 100009: Windows Audit Log Cleared
* **NIST Mapping**: DE.CM-09, RS.MA-02
* **MITRE ATT&CK**: T1070.001 (Indicator Removal: Clear Windows Event Logs)
* **Description**: Detailed detection for windows audit log cleared.
* **Required Telemetry**: windows_eventchannel logs.

### Rule 100010: PSExec Lateral Movement
* **NIST Mapping**: DE.CM-01, DE.AE-02
* **MITRE ATT&CK**: T1021.002 (Remote Services: SMB/Windows Admin Shares)
* **Description**: Detailed detection for psexec lateral movement.
* **Required Telemetry**: windows_eventchannel logs.

### Rule 100011: Repeated Authentication Failures (Multiple Accounts)
* **NIST Mapping**: DE.AE-02, DE.CM-03
* **MITRE ATT&CK**: T1110.003 (Brute Force: Password Spraying)
* **Description**: Detailed detection for repeated authentication failures (multiple accounts).
* **Required Telemetry**: windows_eventchannel logs.

### Rule 100012: Process Injection Indicator (Sysmon)
* **NIST Mapping**: DE.AE-02, RS.AN-08
* **MITRE ATT&CK**: T1055 (Process Injection)
* **Description**: Detailed detection for process injection indicator (sysmon).
* **Required Telemetry**: windows_eventchannel logs.

### Rule 100013: DNS Query to Known C2 Domain
* **NIST Mapping**: ID.RA-03, DE.CM-01
* **MITRE ATT&CK**: T1071.004 (Application Layer Protocol: DNS)
* **Description**: Detailed detection for dns query to known c2 domain.
* **Required Telemetry**: windows_eventchannel logs.

### Rule 100014: Sensitive File Permission Change
* **NIST Mapping**: PR.DS-01, PR.AA-05
* **MITRE ATT&CK**: T1222.002 (File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification)
* **Description**: Detailed detection for sensitive file permission change.
* **Required Telemetry**: auditd logs.

### Rule 100015: Service Installed Outside Business Hours
* **NIST Mapping**: DE.CM-09, DE.AE-03
* **MITRE ATT&CK**: T1543.003 (Create or Modify System Process: Windows Service)
* **Description**: Detailed detection for service installed outside business hours.
* **Required Telemetry**: windows_eventchannel logs.

### Rule 100018: SSH Brute Force Detection
* **NIST Mapping**: DE.CM-01, RS.MA-02
* **MITRE ATT&CK**: T1110.001 (Brute Force: Password Guessing)
* **Description**: Detailed detection for ssh brute force detection.
* **Required Telemetry**: syslog logs.

### Rule 100019: /etc/passwd Modified
* **NIST Mapping**: PR.DS-01, DE.CM-09
* **MITRE ATT&CK**: T1098 (Account Manipulation)
* **Description**: Detailed detection for /etc/passwd modified.
* **Required Telemetry**: auditd logs.

### Rule 100020: /etc/shadow Modified
* **NIST Mapping**: PR.DS-01, DE.CM-09
* **MITRE ATT&CK**: T1003.008 (OS Credential Dumping: /etc/shadow)
* **Description**: Detailed detection for /etc/shadow modified.
* **Required Telemetry**: auditd logs.

### Rule 100021: SSH authorized_keys Modified
* **NIST Mapping**: PR.AA-05, DE.CM-09
* **MITRE ATT&CK**: T1098.004 (Account Manipulation: SSH Authorized Keys)
* **Description**: Detailed detection for ssh authorized_keys modified.
* **Required Telemetry**: auditd logs.

### Rule 100022: SUID/SGID Bit Set on Binary
* **NIST Mapping**: PR.AA-05, DE.AE-02
* **MITRE ATT&CK**: T1548.001 (Abuse Elevation Control Mechanism: Setuid and Setgid)
* **Description**: Detailed detection for suid/sgid bit set on binary.
* **Required Telemetry**: auditd logs.

### Rule 100023: Kernel Module Loaded
* **NIST Mapping**: DE.CM-09, DE.AE-02
* **MITRE ATT&CK**: T1547.006 (Boot or Logon Autostart Execution: Kernel Modules and Extensions)
* **Description**: Detailed detection for kernel module loaded.
* **Required Telemetry**: syslog logs.

### Rule 100024: Log File Deleted or Truncated
* **NIST Mapping**: DE.CM-09, RS.MA-02
* **MITRE ATT&CK**: T1070.002 (Indicator Removal on Host: Clear Linux or Mac System Logs)
* **Description**: Detailed detection for log file deleted or truncated.
* **Required Telemetry**: auditd logs.

### Rule 100025: Execution from /tmp or /dev/shm
* **NIST Mapping**: DE.AE-02, DE.CM-03
* **MITRE ATT&CK**: T1059 (Command and Scripting Interpreter)
* **Description**: Detailed detection for execution from /tmp or /dev/shm.
* **Required Telemetry**: auditd logs.

### Rule 100026: Root Crontab Modification
* **NIST Mapping**: DE.CM-09, PR.DS-01
* **MITRE ATT&CK**: T1053.003 (Scheduled Task/Job: Cron)
* **Description**: Detailed detection for root crontab modification.
* **Required Telemetry**: auditd logs.

### Rule 100027: PowerShell Encoded Command
* **NIST Mapping**: DE.AE-02, DE.CM-03
* **MITRE ATT&CK**: T1059.001 (PowerShell)
* **Description**: Detailed detection for powershell encoded command.
* **Required Telemetry**: windows_sysmon logs.

### Rule 100028: PowerShell Download Cradle
* **NIST Mapping**: DE.AE-02, RS.MA-02
* **MITRE ATT&CK**: T1059.001 (PowerShell)
* **Description**: Detailed detection for powershell download cradle.
* **Required Telemetry**: windows_sysmon logs.

### Rule 100029: Schtasks Creation
* **NIST Mapping**: DE.CM-09, DE.AE-02
* **MITRE ATT&CK**: T1053.005 (Scheduled Task)
* **Description**: Detailed detection for schtasks creation.
* **Required Telemetry**: windows_security logs.

### Rule 100030: Registry Run Key Modification
* **NIST Mapping**: DE.CM-09, PR.DS-01
* **MITRE ATT&CK**: T1547.001 (Registry Run Keys)
* **Description**: Detailed detection for registry run key modification.
* **Required Telemetry**: windows_sysmon logs.

### Rule 100031: Volume Shadow Copy Deleted
* **NIST Mapping**: DE.AE-02, RS.MA-02
* **MITRE ATT&CK**: T1490 (Inhibit System Recovery)
* **Description**: Detailed detection for volume shadow copy deleted.
* **Required Telemetry**: windows_security logs.

### Rule 100032: New Local Admin Account
* **NIST Mapping**: PR.AA-01, DE.CM-03
* **MITRE ATT&CK**: T1136.001 (Local Account)
* **Description**: Detailed detection for new local admin account.
* **Required Telemetry**: windows_security logs.

### Rule 100033: RDP Enabled via Registry
* **NIST Mapping**: PR.AA-05, DE.CM-09
* **MITRE ATT&CK**: T1021.001 (Remote Desktop Protocol)
* **Description**: Detailed detection for rdp enabled via registry.
* **Required Telemetry**: windows_sysmon logs.

### Rule 100034: WMI Event Subscription
* **NIST Mapping**: DE.CM-09, DE.AE-02
* **MITRE ATT&CK**: T1546.003 (WMI Event Subscription)
* **Description**: Detailed detection for wmi event subscription.
* **Required Telemetry**: windows_sysmon logs.

### Rule 100035: LSASS Memory Access
* **NIST Mapping**: DE.AE-02, PR.AA-05
* **MITRE ATT&CK**: T1003.001 (LSASS Memory)
* **Description**: Detailed detection for lsass memory access.
* **Required Telemetry**: windows_sysmon logs.

### Rule 100036: Mimikatz Indicators
* **NIST Mapping**: DE.AE-02, RS.MA-02
* **MITRE ATT&CK**: T1003 (OS Credential Dumping)
* **Description**: Detailed detection for mimikatz indicators.
* **Required Telemetry**: windows_sysmon logs.

### Rule 100037: Pass-the-Hash Indicators
* **NIST Mapping**: DE.AE-02, DE.CM-01
* **MITRE ATT&CK**: T1550.002 (Pass the Hash)
* **Description**: Detailed detection for pass-the-hash indicators.
* **Required Telemetry**: windows_security logs.

### Rule 100038: DCSync Attack
* **NIST Mapping**: DE.AE-02, ID.RA-03
* **MITRE ATT&CK**: T1003.006 (DCSync)
* **Description**: Detailed detection for dcsync attack.
* **Required Telemetry**: windows_security logs.

### Rule 100039: Kerberoasting Indicators
* **NIST Mapping**: DE.AE-02, ID.RA-03
* **MITRE ATT&CK**: T1558.003 (Kerberoasting)
* **Description**: Detailed detection for kerberoasting indicators.
* **Required Telemetry**: windows_security logs.

### Rule 100040: Multiple Account Lockouts
* **NIST Mapping**: DE.AE-02, DE.CM-03
* **MITRE ATT&CK**: T1110 (Brute Force)
* **Description**: Detailed detection for multiple account lockouts.
* **Required Telemetry**: windows_security logs.

### Rule 100041: Linux Passwd Accessed by Non-Root
* **NIST Mapping**: PR.AA-05, DE.CM-03
* **MITRE ATT&CK**: T1003.008 (/etc/passwd and /etc/shadow)
* **Description**: Detailed detection for linux passwd accessed by non-root.
* **Required Telemetry**: auditd logs.

### Rule 100042: Reverse Shell Spawned
* **NIST Mapping**: DE.AE-02, RS.MA-02
* **MITRE ATT&CK**: T1059.004 (Unix Shell)
* **Description**: Detailed detection for reverse shell spawned.
* **Required Telemetry**: auditd logs.

### Rule 100043: Base64 Encoded Command
* **NIST Mapping**: DE.AE-02, DE.CM-03
* **MITRE ATT&CK**: T1027 (Obfuscated Files or Information)
* **Description**: Detailed detection for base64 encoded command.
* **Required Telemetry**: auditd logs.

### Rule 100044: DNS Tunneling Indicators
* **NIST Mapping**: DE.CM-01, DE.AE-03
* **MITRE ATT&CK**: T1071.004 (DNS)
* **Description**: Detailed detection for dns tunneling indicators.
* **Required Telemetry**: windows_sysmon logs.

### Rule 100045: TOR Exit Node Connection
* **NIST Mapping**: DE.CM-01, DE.AE-03
* **MITRE ATT&CK**: T1090.003 (Multi-hop Proxy: TOR)
* **Description**: Detailed detection for tor exit node connection.
* **Required Telemetry**: iptables logs.

### Rule 100046: Beaconing Behaviour
* **NIST Mapping**: DE.AE-02, DE.CM-01
* **MITRE ATT&CK**: T1071.001 (Web Protocols)
* **Description**: Detailed detection for beaconing behaviour.
* **Required Telemetry**: windows_sysmon logs.

### Rule 100047: Certutil Used to Download File
* **NIST Mapping**: DE.AE-02, DE.CM-03
* **MITRE ATT&CK**: T1105 (Ingress Tool Transfer)
* **Description**: Detailed detection for certutil used to download file.
* **Required Telemetry**: windows_sysmon logs.

### Rule 100048: Regsvr32 Executing Remote Script
* **NIST Mapping**: DE.AE-02, DE.CM-03
* **MITRE ATT&CK**: T1218 (Signed Binary Proxy Execution)
* **Description**: Detailed detection for regsvr32 executing remote script.
* **Required Telemetry**: windows_sysmon logs.

### Rule 100049: Admin Account Used Outside Business Hours
* **NIST Mapping**: GV.PO-01, DE.CM-03
* **MITRE ATT&CK**: T1078 (Valid Accounts)
* **Description**: Detailed detection for admin account used outside business hours.
* **Required Telemetry**: windows_security logs.

### Rule 100050: Backup Process Failure
* **NIST Mapping**: RC.RP-01, DE.CM-09
* **MITRE ATT&CK**: T1490 (Inhibit System Recovery)
* **Description**: Detailed detection for backup process failure.
* **Required Telemetry**: syslog logs.

### Rule 100051: Sysmon Event Log Cleared
* **NIST Mapping**: DE.CM-09, RS.MA-02
* **MITRE ATT&CK**: T1070.001 (Indicator Removal: Clear Windows Event Logs)
* **Description**: Detailed detection for sysmon event log cleared.
* **Required Telemetry**: windows_eventchannel logs.

### Rule 100052: Windows Defender Tampering via PowerShell
* **NIST Mapping**: DE.AE-02, PR.DS-01
* **MITRE ATT&CK**: T1562.001 (Impair Defenses: Disable or Modify Tools)
* **Description**: Detailed detection for windows defender tampering via powershell.
* **Required Telemetry**: windows_sysmon logs.

### Rule 100053: Execution from Recycle Bin
* **NIST Mapping**: DE.CM-03, DE.AE-02
* **MITRE ATT&CK**: T1036 (Masquerading)
* **Description**: Detailed detection for execution from recycle bin.
* **Required Telemetry**: windows_sysmon logs.

