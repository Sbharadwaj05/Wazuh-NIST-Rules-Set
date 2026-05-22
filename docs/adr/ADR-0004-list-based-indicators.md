# ADR-0004: List-based indicators for ports and domains

Date: 2026-05-22
Status: Accepted

## Context
Indicator sets such as rare ports and C2 domains need frequent updates and vary by environment.

## Decision
Store indicators in Wazuh CDB list files under lists/ and reference them from rules using the list lookup. Initial lists are rare-ports and c2-domains.

## Consequences
- Indicator updates do not require rule edits.
- Environments can customize lists without touching rule logic.
- List deployment must be part of the install process.
