# ADR-0002: Rule XML template with inline analysis

Date: 2026-05-22
Status: Accepted

## Context
Wazuh rulesets often lack context about intent, false positives, and tuning. We want these rules to be usable in one go.

## Decision
Each rule is a standalone XML file with a consistent header block describing intent, false positives, tuning guidance, assumptions, and limitations. Rules include NIST CSF and MITRE references inline and use consistent group tags.

## Consequences
- Reviewers and users can tune rules without external docs.
- Rule files are longer but significantly more usable.
- Contributors must maintain the header block for every rule.
