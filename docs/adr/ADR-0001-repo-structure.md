# ADR-0001: Repository structure and NIST-first organization

Date: 2026-05-22
Status: Accepted

## Context
We needed a repo layout that is easy to navigate by NIST CSF control and scales as rules grow. Changing structure later would be costly.

## Decision
Use a dedicated ruleset repo with top-level folders for docs, rules, tests, mappings, lists, and dashboards. Organize rules by NIST CSF function and category (e.g., rules/DE.CM, rules/DE.AE, rules/PR.AA, rules/PR.DS, rules/RS.AN, rules/ID.RA).

## Consequences
- Contributors can jump directly to a control area without reading the whole repo.
- Mapping and testing artifacts are centralized and consistent.
- Category folders must be maintained even when initially empty.
