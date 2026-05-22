# ADR-0003: Rule ID range and file naming

Date: 2026-05-22
Status: Accepted

## Context
We need stable identifiers for rules and filenames that map clearly to NIST controls.

## Decision
Use rule IDs in the 100000 range for this pack and name files using the control code plus a short slug, for example DE.CM-01_ssh-bruteforce.xml.

## Consequences
- IDs are predictable and easy to reference in mapping tables and dashboards.
- File names are sortable by control and human readable.
- Future packs must avoid ID collisions.
