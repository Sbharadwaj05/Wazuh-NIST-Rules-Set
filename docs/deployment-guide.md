# Deployment Guide: Wazuh NIST CSF Rule Pack

This guide walks you through deploying the NIST CSF 2.0 mapped rule set to a production or laboratory Wazuh environment.

---

## 1. Prerequisites
- **Wazuh Manager:** v4.8.x or higher installed on a Linux VM (e.g., Ubuntu).
- **Wazuh Agents:** Installed on monitored workloads (Linux and/or Windows).
- **Administrative Privileges:** `sudo` access on the manager and administrative shells on agents.

---

## 2. Deploying Custom Rules & Lists

Wazuh loads custom rules from `/var/ossec/etc/rules/` and CDB lists from `/var/ossec/etc/lists/`.

### Step 1: Copy Rules
Copy all XML files from the `rules/` directory of this repository into the manager's rules directory:
```bash
sudo cp -r rules/* /var/ossec/etc/rules/
sudo chown -R wazuh:wazuh /var/ossec/etc/rules/
sudo chmod 660 /var/ossec/etc/rules/*/*.xml
```

### Step 2: Copy & Configure CDB Lists
1. Copy the raw list source files to the manager's lists directory:
   ```bash
   sudo mkdir -p /var/ossec/etc/lists/
   sudo cp lists/* /var/ossec/etc/lists/
   sudo chown -R wazuh:wazuh /var/ossec/etc/lists/
   sudo chmod 660 /var/ossec/etc/lists/*
   ```

2. Register the CDB lists in the manager's `/var/ossec/etc/ossec.conf` file. Open the file:
   ```bash
   sudo nano /var/ossec/etc/ossec.conf
   ```
   Locate the `<ruleset>` block and add the `<list>` declarations for our custom lists:
   ```xml
   <ruleset>
     <!-- Pre-existing default rules and lists declarations -->
     <list>etc/lists/rare-ports</list>
     <list>etc/lists/c2-domains</list>
   </ruleset>
   ```

3. **Compile the Lists:**
   Wazuh uses compiled binary CDB databases for fast lookups. When you restart the Wazuh manager, it will automatically compile the plain text lists specified in `ossec.conf` into `.cdb` files.

   However, if you want to manually compile the lists immediately to verify their syntax, you can use the `ossec-makelist` utility:
   ```bash
   sudo /var/ossec/bin/ossec-makelist
   ```
   Verify that the `.cdb` files have been created successfully:
   ```bash
   ls -la /var/ossec/etc/lists/*.cdb
   ```

---

## 3. Agent Log Collection Setup

To trigger these rules, you must configure the Wazuh agents to collect and forward the appropriate logs.

### A. Linux Agents (Ubuntu / Mint / RHEL)
1. **auditd (File Read & Permission Changes):**
   Install auditd and configure rules to monitor sensitive paths:
   ```bash
   sudo apt-get install auditd
   ```
   Add rules to `/etc/audit/rules.d/audit.rules` or via command line:
   ```bash
   # Monitor cron modifications
   sudo auditctl -w /etc/crontab -p wa -k cron-changes
   sudo auditctl -w /etc/cron.d/ -p wa -k cron-changes
   
   # Monitor passwd/shadow reads
   sudo auditctl -w /etc/passwd -p r -k sensitive-read
   sudo auditctl -w /etc/shadow -p r -k sensitive-read
   
   # Monitor file permission changes in sensitive folders
   sudo auditctl -w /etc/ -p wa -k perm-changes
   ```
   Ensure the Wazuh agent's `ossec.conf` is configured to read the audit log:
   ```xml
   <localfile>
     <log_format>audit</log_format>
     <location>/var/log/audit/audit.log</location>
   </localfile>
   ```

2. **System Logs (sshd & sudo):**
   Forward auth and syslog events via agent localfile:
   ```xml
   <localfile>
     <log_format>syslog</log_format>
     <location>/var/log/auth.log</location>
   </localfile>
   ```

3. **iptables (Egress Network Connections):**
   Configure logging for outbound TCP connections:
   ```bash
   sudo iptables -A OUTPUT -p tcp -j LOG --log-prefix "OUTBOUND-BLOCK: "
   ```
   Configure agent to collect syslog if kernel logs are forwarded there, or read `/var/log/kern.log`.

---

### B. Windows Agents
Add the following event channels inside the Windows agent's `ossec.conf` inside the `<ossec_config>` section:
```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
*Note: Make sure Sysmon is installed and running with a configuration that captures Event ID 8 (CreateRemoteThread) and Event ID 22 (DNS queries).*

---

## 4. Verification and Testing

### Syntax Check
Before restarting the manager, always validate the rule syntax:
```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```
Ensure there are no errors listed for the custom XML files.

### Restarting the Manager
Once validated, restart the service:
```bash
sudo systemctl restart wazuh-manager
```

### Synthetic Testing
Run the automated test runner in this repository to verify rule parsing and detection correctness:
```bash
./tests/test-runner.sh
```
All synthetic tests should complete with a `[PASS]` result.
