# ADR-0007: Human and machine readable mapping artifacts

Date: 2026-05-22
Status: Accepted

## Context
Security teams need a readable mapping table, and tooling builders need a structured mapping file.

## Decision
Maintain a markdown table mapping NIST CSF to rule IDs and a JSON mapping file for programmatic use.

## Consequences
- Stakeholders can reference a single table.
- Tools can ingest mappings without scraping markdown.
- Both artifacts must be updated together.
