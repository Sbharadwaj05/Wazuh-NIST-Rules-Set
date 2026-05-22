# Testing Guide

## Lab Requirements
- Wazuh manager (4.x) with rules and lists deployed
- Linux agent (Mint) with auditd enabled and sudo/sshd logs forwarded
- Windows agent with Sysmon installed and Security/System/Sysmon channels collected

## Lab Topology
- Manager: Ubuntu VM running Wazuh manager
- Agent: Linux Mint VM
- Agent: Windows workstation (local machine)

## Baseline Telemetry Prerequisites
Linux agent:
- auditd rules cover /etc/passwd, /etc/shadow, /etc/cron*, /var/spool/cron, and
	permission changes on sensitive paths (for PR.DS and DE.CM rules)
- sshd and sudo logs forwarded via syslog
- iptables logging enabled for outbound connections on monitored ports

Windows agent:
- Event Channels: Security, System, Microsoft-Windows-Sysmon/Operational
- Sysmon configuration includes Event ID 8 (CreateRemoteThread) and Event ID 22
	(DNS query)

## Lab Workflow
1. Copy rules to /var/ossec/etc/rules and lists to /var/ossec/etc/lists on the manager.
2. Restart the Wazuh manager and confirm the rules load.
3. Trigger detections from the agents and verify alerts in the Wazuh UI.
4. Capture tuning notes, false positives, and any decoder gaps.

## Rule Test Checklist
Use this checklist for repeatable, auditable validation. Each rule should have a
trigger test and a benign test.

| Rule ID | Rule name | Platform | Log source | Trigger | Expected |
|---|---|---|---|---|---|
| 100001 | SSH Brute Force Detection | Linux | sshd/syslog | 5 failed SSH logins from same source IP within 60s | Alert for rule 100001 |
| 100005 | Outbound Connection to Monitored Port | Linux | iptables | Outbound connection to a port in lists/rare-ports (with iptables logging enabled) | Alert for rule 100005 |
| 100010 | PSExec Lateral Movement | Windows | Event Channel (System) | Run PSExec to create PSEXESVC service | Alert for rule 100010 |
| 100015 | Service Installed Outside Business Hours | Windows | Event Channel (System) | Install a new service outside 08:00-18:00 (or temporarily adjust time window) | Alert for rule 100015 |
| 100004 | Cron Job Modification | Linux | auditd | Modify /etc/crontab or /etc/cron.d/* with auditd enabled | Alert for rule 100004 |
| 100009 | Windows Audit Log Cleared | Windows | Event Channel (Security) | Clear Security log (lab only) to generate Event ID 1102 | Alert for rule 100009 |
| 100007 | Web Shell Indicators in HTTP Requests | Linux | Web access logs | HTTP request containing cmd= or /shell.php to a web server that logs requests | Alert for rule 100007 |
| 100008 | Large File Exfiltration (>=100MB) | Linux | Proxy/Web logs | Generate a log line with bytes=100000000+ for POST/PUT (or simulate log injection) | Alert for rule 100008 |
| 100011 | Repeated Authentication Failures | Windows | Event Channel (Security) | 5 failed logons (4625, logonType 3) from same source IP within 5 min | Alert for rule 100011 |
| 100003 | New User Account Created | Linux | syslog | Run useradd to create a local account | Alert for rule 100003 |
| 100002 | Sudo Privilege Escalation | Linux | sudo | Run sudo command that logs USER=root and COMMAND= | Alert for rule 100002 |
| 100006 | Sensitive File Read (/etc/passwd or /etc/shadow) | Linux | auditd | Read /etc/shadow or /etc/passwd with auditd enabled | Alert for rule 100006 |
| 100014 | Sensitive File Permission Change | Linux | auditd | chmod/chown/setfacl on /etc, /root, /var/www, or /opt | Alert for rule 100014 |
| 100012 | Process Injection Indicator (Sysmon) | Windows | Sysmon | Generate Sysmon Event ID 8 via a benign CreateRemoteThread test harness | Alert for rule 100012 |
| 100013 | DNS Query to Known C2 Domain | Windows | Sysmon | Query a domain in lists/c2-domains (e.g., example-c2.bad) to log Event ID 22 | Alert for rule 100013 |

## Notes
- Use your Ubuntu VM (manager), Linux Mint (agent), and Windows PC (agent) for end-to-end validation.
- Add a Kali VM later for attack simulation to validate adversary-style behaviors.
- The ./tests/test-runner.sh script remains optional for synthetic log checks.
- Some rules are time or list based; adjust windows and lists for reliable lab triggers.
