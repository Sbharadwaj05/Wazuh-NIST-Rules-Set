
echo "--- Batch 6 Additions ---"
run_test 100051 "tests/sample-logs/de-ae-04/sysmon-event-log-cleared/trigger.log" true "Sysmon log cleared - trigger"
run_test 100051 "tests/sample-logs/de-ae-04/sysmon-event-log-cleared/benign.log" false "Sysmon log cleared - benign"
run_test 100052 "tests/sample-logs/de-ae-04/windows-defender-tampering/trigger.log" true "Defender tamper - trigger"
run_test 100052 "tests/sample-logs/de-ae-04/windows-defender-tampering/benign.log" false "Defender tamper - benign"
run_test 100053 "tests/sample-logs/de-ae-04/execution-from-recycle-bin/trigger.log" true "Recycle bin exec - trigger"
run_test 100053 "tests/sample-logs/de-ae-04/execution-from-recycle-bin/benign.log" false "Recycle bin exec - benign"
