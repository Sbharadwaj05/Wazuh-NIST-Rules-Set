# Wazuh NIST CSF Detection Rule Pack

Wazuh detection rules mapped to NIST CSF 2.0, with MITRE ATT&CK mapping, sample logs, and automated tests.

## Status
Scaffolded repository structure. Rule mapping and authoring in progress.

## Structure
- docs/ - guides and mapping table
- rules/ - rule XML grouped by NIST CSF function/category
- tests/ - sample logs and test runner
- mappings/ - machine-readable NIST/MITRE/Wazuh mapping
- dashboards/ - dashboard exports

## Next steps
- Finalize the rule mapping spreadsheet.
- Author the first rule set in rules/DE.CM.
- Expand sample logs and wire into the test runner.
