# ADR-0008: Baseline log sources and decoders

Date: 2026-05-22
Status: Accepted

## Context
Rules need predictable fields and decoders to be reliable in one pass.

## Decision
Target a baseline of Wazuh decoders and sources: sshd, sudo, auditd, iptables, and windows_eventchannel with Sysmon for Windows detections.

## Consequences
- Rules are immediately useful on standard Linux and Windows agent setups.
- Environments with different log sources must adjust rules or add decoders.
