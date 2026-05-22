# Deployment Guide

## Prerequisites
- Wazuh Manager 4.x (tested versions will be listed here)

## Lab Topology
- Ubuntu VM: Wazuh manager
- Linux Mint VM: Wazuh agent
- Windows workstation: Wazuh agent

## Paths (Manager)
- Rules: /var/ossec/etc/rules/
- Lists: /var/ossec/etc/lists/

## Install
1. Copy rules in rules/ to /var/ossec/etc/rules/
2. Copy lists in lists/ to /var/ossec/etc/lists/
3. Restart the Wazuh manager

## Agent Configuration (Lab)
Linux Mint agent:
- Ensure auditd is enabled and collecting file access/permission changes
- Confirm sshd and sudo logs are forwarded via syslog
- Enable iptables logging for outbound connections on monitored ports

Windows agent:
- Collect Event Channels: Security, System, Microsoft-Windows-Sysmon/Operational
- Install Sysmon and configure it to log Event ID 8 and 22

## Verify
- Check /var/ossec/logs/ossec.log for rule load errors
- Use /var/ossec/bin/wazuh-logtest for synthetic checks (optional)
- Trigger a known lab test and confirm the alert appears in Wazuh UI

## Alert integrations
- Email, Slack, webhook, and SOAR integrations will be documented here

## Dashboard import
- Import steps for OpenSearch Dashboards will be documented here
