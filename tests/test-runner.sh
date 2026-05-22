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

  result=$(echo "$(cat $log_file)" | /var/ossec/bin/wazuh-logtest -q 2>&1 | grep "Rule Id:" | grep -o '[0-9]*')

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
run_test 100001 "tests/sample-logs/de-cm-01/ssh-bruteforce/trigger.log" true "SSH brute force - trigger"
run_test 100001 "tests/sample-logs/de-cm-01/ssh-bruteforce/benign.log" false "SSH brute force - benign single failure"

echo ""
echo "Results: $PASS passed, $FAIL failed"
