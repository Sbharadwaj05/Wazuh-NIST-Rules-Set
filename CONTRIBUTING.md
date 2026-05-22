# Contributing

Thanks for helping improve this ruleset.

## Requirements
- Each rule must include the full comment block (description, false positives, tuning guidance).
- Add tests: one trigger and one benign log under tests/sample-logs/<rule-id>/.
- Update docs/nist-mapping-table.md and mappings/nist-csf-mitre-wazuh.json for any new rule.

## Style
- Keep rule IDs in the 100000 range.
- Use consistent NIST CSF tags in <group>.
- Prefer one rule per file.

## Testing
- Run tests/test-runner.sh before submitting changes.
