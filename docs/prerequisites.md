# Agent Configuration & Prerequisites

The detection rules in this pack require specific telemetry to function correctly. If your endpoints are not configured to generate these logs, or if the Wazuh agent is not configured to forward them, the rules will never trigger.

This guide details the exact configurations required for both Windows and Linux endpoints.

---

## 🪟 Windows Endpoints

### 1. Enable Native Windows Auditing
Certain rules (like detecting audit log clearing or specific sensitive file access) rely on native Windows Security Auditing.
You must enable these via Group Policy Object (GPO) or Local Security Policy (`secpol.msc`):
*   **Audit File System**: Success/Failure (Required for file permission monitoring).
*   **Audit Process Creation**: Success (Required if not using Sysmon).
*   **Audit Logon Events**: Success/Failure (Required for spray rule `100011`, Pass-the-Hash `100037`, Admin After Hours `100049`).
*   **Audit System Events**: Success/Failure (Required to detect audit log clearing - rule `100009`).
*   **Audit Account Management**: Success/Failure (Required for new local admin `100032`, account lockout `100040`).
*   **Audit Directory Service Access**: Success/Failure (Required for DCSync `100038`).
*   **Audit Kerberos Authentication Service**: Success/Failure (Required for Kerberoasting `100039`).

### 2. Install Microsoft Sysmon
Several rules heavily rely on Sysmon for high-fidelity telemetry, notably:
*   **Process Creation (Event 1)**: Required for LOLBins (Certutil, Regsvr32), Mimikatz, PowerShell encoding, Schtasks, and VSSAdmin deletion.
*   **Network Connection (Event 3)**: Required for beaconing detection (`100046`).
*   **Process Injection (Event 8)**: Required for Rule `100012`.
*   **Registry Events (Event 13)**: Required for Run key and RDP modifications (`100030`, `100033`).
*   **WMI Activity (Event 19-21)**: Required for WMI event subscription persistence (`100034`).
*   **DNS Query (Event 22)**: Required for C2 domains and DNS tunneling (`100013`, `100044`).

**Prerequisite**: Install Sysmon with a robust configuration file (e.g., SwiftOnSecurity or SwiftOnSecurity-forked configs).
```powershell
Sysmon.exe -i sysmonconfig.xml -accepteula
```

### 3. Wazuh Agent `<localfile>` Configuration
The Wazuh agent must be instructed to read the Windows Event Channels as JSON. Add the following to your agent's `ossec.conf` (or via central agent configuration):

```xml
<!-- Read Windows Security Event Log as JSON -->
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>

<!-- Read Sysmon Operational Log as JSON -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

> [!IMPORTANT]
> The rules in this pack expect `<decoded_as>json</decoded_as>`. If your agent is configured to send logs in the legacy plain-text format (`eventlog`), the rules will **not** evaluate correctly. Always use `eventchannel`.

---

## 🐧 Linux Endpoints

### 1. Install and Configure `auditd`
The Linux Audit Daemon (`auditd`) is strictly required for several core rules:
*   **Cron Job Modification (Rule 100004)**
*   **Sensitive Permission Change (Rule 100014)**
*   **Passwd/Shadow Read (Rule 100006)**

**Prerequisite Setup**:
Install `auditd` on the endpoint:
```bash
sudo apt-get install auditd  # Debian/Ubuntu
sudo yum install audit  # RHEL/CentOS
```

Add the following watch rules to `/etc/audit/rules.d/audit.rules` (or configure via Wazuh's `syscheck` using `audit` options):
```text
# Track modifications to cron
-w /etc/cron.d/ -p wa -k cron_mod
-w /etc/cron.daily/ -p wa -k cron_mod
-w /etc/cron.hourly/ -p wa -k cron_mod
-w /var/spool/cron/crontabs/ -p wa -k cron_mod

# Track read access to sensitive authentication files
-w /etc/shadow -p r -k shadow_read
-w /etc/passwd -p r -k passwd_read

# Track permission changes (chmod, chown)
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
```
Restart the `auditd` service after modifying rules.

### 2. Configure `iptables` Logging
For **Outbound Rare Port Egress (Rule 100005)** to trigger, the Linux kernel must log outbound connections.

**Example `iptables` rule:**
```bash
# Log outbound traffic before accepting it
iptables -A OUTPUT -m state --state NEW -j LOG --log-prefix "iptables_out: "
```
*Note: Depending on your system configuration, this traffic will be logged to `/var/log/kern.log` or `/var/log/syslog`.*

### 3. Wazuh Agent `<localfile>` Configuration
The Wazuh agent needs to monitor standard Linux log paths. Ensure the following paths are configured in the agent's `ossec.conf`:

```xml
<!-- System Logs (includes iptables and sudo) -->
<localfile>
  <location>/var/log/syslog</location>
  <log_format>syslog</log_format>
</localfile>

<!-- Authentication Logs (SSH, Sudo) -->
<localfile>
  <location>/var/log/auth.log</location>
  <log_format>syslog</log_format>
</localfile>

<!-- Auditd Logs -->
<localfile>
  <location>/var/log/audit/audit.log</location>
  <log_format>audit</log_format>
</localfile>
```

---

## 🌐 Application Servers & Proxies

### Web Access Logs
For rules like **Web Shell Indicators (Rule 100007)**, ensure the agent is configured to ingest Apache or Nginx access logs:
```xml
<localfile>
  <location>/var/log/nginx/access.log</location>
  <log_format>apache</log_format> <!-- wazuh treats both apache and nginx as 'apache' log format -->
</localfile>
```

### Proxy Logs (Large File Exfiltration)
For **Rule 100008 (Large File Exfiltration)**, the proxy server (e.g., Squid) must log bytes sent and be forwarded via syslog format with the program name `proxy`:
```xml
<localfile>
  <location>/var/log/squid/access.log</location>
  <log_format>syslog</log_format>
</localfile>
```
*(Ensure the Squid logging format prefixes the line with `proxy: ` to trigger our custom Phase 2 decoder).*
