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

  result=$(cat "$log_file" | /var/ossec/bin/wazuh-logtest 2>&1 | grep -E "^[[:space:]]*id:" | grep -o '[0-9]*')

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

run_test 100011 "tests/sample-logs/de-ae-02/repeated-auth-failures/trigger.log" true "Windows logon failure - trigger"
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

echo ""
echo "Results: $PASS passed, $FAIL failed"
