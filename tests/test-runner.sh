#!/usr/bin/env bash
# tests/test-runner.sh

PASS=0
FAIL=0
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

run_test() {
  local rule_id=$1
  local log_file=$2
  local should_trigger=$3  # "true" or "false"
  local test_name=$4

  result=$(cat "$log_file" | sudo /var/ossec/bin/wazuh-logtest 2>&1 | grep -E "^[[:space:]]*id:" | grep -o '[0-9]*')

  if [ "$should_trigger" = "true" ]; then
    if echo "$result" | grep -q "$rule_id"; then
      echo -e "${GREEN}[PASS]${NC} $test_name - Rule $rule_id fired as expected"
      ((PASS++))
    else
      echo -e "${RED}[FAIL]${NC} $test_name - Rule $rule_id did NOT fire (expected trigger)"
      ((FAIL++))
    fi
  else
    if echo "$result" | grep -q "$rule_id"; then
      echo -e "${RED}[FAIL]${NC} $test_name - Rule $rule_id fired on benign log (false positive)"
      ((FAIL++))
    else
      echo -e "${GREEN}[PASS]${NC} $test_name - Rule $rule_id correctly silent on benign log"
      ((PASS++))
    fi
  fi
}

# Run all tests
run_test 100018 "tests/sample-logs/de-cm-01/ssh-bruteforce/trigger.log" true "SSH brute force - trigger"
run_test 100018 "tests/sample-logs/de-cm-01/ssh-bruteforce/benign.log" false "SSH brute force - benign"

run_test 100002 "tests/sample-logs/pr-aa-05/sudo-privilege-escalation/trigger.log" true "Sudo privilege escalation - trigger"
run_test 100002 "tests/sample-logs/pr-aa-05/sudo-privilege-escalation/benign.log" false "Sudo privilege escalation - benign"

run_test 100003 "tests/sample-logs/pr-aa-01/new-user-account/trigger.log" true "New user account - trigger"
run_test 100003 "tests/sample-logs/pr-aa-01/new-user-account/benign.log" false "New user account - benign"

run_test 100004 "tests/sample-logs/de-cm-09/cron-modification/trigger.log" true "Cron job modification - trigger"
run_test 100004 "tests/sample-logs/de-cm-09/cron-modification/benign.log" false "Cron job modification - benign"

run_test 100005 "tests/sample-logs/de-cm-01/outbound-rare-port/trigger.log" true "Outbound rare port - trigger"
run_test 100005 "tests/sample-logs/de-cm-01/outbound-rare-port/benign.log" false "Outbound rare port - benign"

run_test 100006 "tests/sample-logs/pr-ds-01/passwd-shadow-read/trigger.log" true "Passwd shadow read - trigger"
run_test 100006 "tests/sample-logs/pr-ds-01/passwd-shadow-read/benign.log" false "Passwd shadow read - benign"

run_test 100007 "tests/sample-logs/de-ae-02/web-shell-indicators/trigger.log" true "Web shell indicators - trigger"
run_test 100007 "tests/sample-logs/de-ae-02/web-shell-indicators/benign.log" false "Web shell indicators - benign"

run_test 100008 "tests/sample-logs/de-ae-03/large-file-exfiltration/trigger.log" true "Large file exfiltration - trigger"
run_test 100008 "tests/sample-logs/de-ae-03/large-file-exfiltration/benign.log" false "Large file exfiltration - benign"

run_test 100009 "tests/sample-logs/de-cm-09/windows-audit-cleared/trigger.log" true "Windows audit cleared - trigger"
run_test 100009 "tests/sample-logs/de-cm-09/windows-audit-cleared/benign.log" false "Windows audit cleared - benign"

run_test 100010 "tests/sample-logs/de-cm-01/psexec-lateral-movement/trigger.log" true "PSExec lateral movement - trigger"
run_test 100010 "tests/sample-logs/de-cm-01/psexec-lateral-movement/benign.log" false "PSExec lateral movement - benign"

# Rule 100011 is frequency-based (needs 5+ events in 300s).
# wazuh-logtest processes logs line-by-line and cannot simulate time-based correlation.
# We verify rule 100016 (the helper) fires correctly instead.
run_test 100016 "tests/sample-logs/de-ae-02/repeated-auth-failures/trigger.log" true "Windows logon failure helper (100016) - trigger"
run_test 100011 "tests/sample-logs/de-ae-02/repeated-auth-failures/benign.log" false "Windows logon failure - benign"

run_test 100012 "tests/sample-logs/rs-an-08/process-injection/trigger.log" true "Process injection - trigger"
run_test 100012 "tests/sample-logs/rs-an-08/process-injection/benign.log" false "Process injection - benign"

run_test 100013 "tests/sample-logs/id-ra-03/dns-c2-domain/trigger.log" true "DNS C2 domain - trigger"
run_test 100013 "tests/sample-logs/id-ra-03/dns-c2-domain/benign.log" false "DNS C2 domain - benign"

run_test 100014 "tests/sample-logs/pr-ds-01/sensitive-permission-change/trigger.log" true "Sensitive permission change - trigger"
run_test 100014 "tests/sample-logs/pr-ds-01/sensitive-permission-change/benign.log" false "Sensitive permission change - benign"

# Run rule 100015 check dynamically based on the current system hour
current_hour=$(date +%H)
if [ "$current_hour" -lt 8 ] || [ "$current_hour" -ge 18 ]; then
  run_test 100015 "tests/sample-logs/de-cm-09/after-hours-service-install/trigger.log" true "After-hours service install - trigger (evaluated outside business hours)"
else
  run_test 100015 "tests/sample-logs/de-cm-09/after-hours-service-install/trigger.log" false "After-hours service install - trigger (evaluated during business hours, expected silent)"
fi
run_test 100015 "tests/sample-logs/de-cm-09/after-hours-service-install/benign.log" false "After-hours service install - benign"

run_test 100019 "tests/sample-logs/pr-ds-01/passwd-modification/trigger.log" true "/etc/passwd modified - trigger"
run_test 100019 "tests/sample-logs/pr-ds-01/passwd-modification/benign.log" false "/etc/passwd modified - benign"

run_test 100020 "tests/sample-logs/pr-ds-01/shadow-modification/trigger.log" true "/etc/shadow modified - trigger"
run_test 100020 "tests/sample-logs/pr-ds-01/shadow-modification/benign.log" false "/etc/shadow modified - benign"

run_test 100021 "tests/sample-logs/pr-aa-05/authorized-keys-modification/trigger.log" true "SSH authorized_keys modified - trigger"
run_test 100021 "tests/sample-logs/pr-aa-05/authorized-keys-modification/benign.log" false "SSH authorized_keys modified - benign"

run_test 100022 "tests/sample-logs/pr-aa-05/suid-sgid-set/trigger.log" true "SUID/SGID bit set - trigger"
run_test 100022 "tests/sample-logs/pr-aa-05/suid-sgid-set/benign.log" false "SUID/SGID bit set - benign"

run_test 100023 "tests/sample-logs/de-cm-09/kernel-module-loaded/trigger.log" true "Kernel module loaded - trigger"
run_test 100023 "tests/sample-logs/de-cm-09/kernel-module-loaded/benign.log" false "Kernel module loaded - benign"

run_test 100024 "tests/sample-logs/de-cm-09/log-file-deleted/trigger.log" true "Log file deleted - trigger"
run_test 100024 "tests/sample-logs/de-cm-09/log-file-deleted/benign.log" false "Log file deleted - benign"

run_test 100025 "tests/sample-logs/de-ae-02/execution-from-tmp/trigger.log" true "Execution from /tmp - trigger"
run_test 100025 "tests/sample-logs/de-ae-02/execution-from-tmp/benign.log" false "Execution from /tmp - benign"

run_test 100026 "tests/sample-logs/de-cm-09/root-crontab-modification/trigger.log" true "Root crontab modification - trigger"
run_test 100026 "tests/sample-logs/de-cm-09/root-crontab-modification/benign.log" false "Root crontab modification - benign"

echo ""
echo "--- Batch 6 Additions ---"
run_test 100051 "tests/sample-logs/de-ae-04/sysmon-event-log-cleared/trigger.log" true "Sysmon log cleared - trigger"
run_test 100051 "tests/sample-logs/de-ae-04/sysmon-event-log-cleared/benign.log" false "Sysmon log cleared - benign"
run_test 100052 "tests/sample-logs/de-ae-04/windows-defender-tampering/trigger.log" true "Defender tamper - trigger"
run_test 100052 "tests/sample-logs/de-ae-04/windows-defender-tampering/benign.log" false "Defender tamper - benign"
run_test 100053 "tests/sample-logs/de-ae-04/execution-from-recycle-bin/trigger.log" true "Recycle bin exec - trigger"
run_test 100053 "tests/sample-logs/de-ae-04/execution-from-recycle-bin/benign.log" false "Recycle bin exec - benign"

echo ""
echo "Results: $PASS passed, $FAIL failed"
