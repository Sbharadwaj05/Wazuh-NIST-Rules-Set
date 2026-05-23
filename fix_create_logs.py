with open('tests/create_logs.py', 'r') as f:
    content = f.read()

content = content.replace(
    '{"win":{"system":{"eventID":"1"}, "eventdata":{"commandLine":"powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true"}}}',
    '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon", "eventID":"1"}, "eventdata":{"commandLine":"powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true"}}}'
)

content = content.replace(
    '{"win":{"system":{"eventID":"1"}, "eventdata":{"commandLine":"powershell.exe Get-Process"}}}',
    '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon", "eventID":"1"}, "eventdata":{"commandLine":"powershell.exe Get-Process"}}}'
)

content = content.replace(
    '{"win":{"system":{"eventID":"1"}, "eventdata":{"commandLine":"C:\\\\$Recycle.bin\\\\malware.exe"}}}',
    '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon", "eventID":"1"}, "eventdata":{"commandLine":"C:\\\\$Recycle.bin\\\\malware.exe"}}}'
)

content = content.replace(
    '{"win":{"system":{"eventID":"1"}, "eventdata":{"commandLine":"C:\\\\Windows\\\\System32\\\\cmd.exe"}}}',
    '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon", "eventID":"1"}, "eventdata":{"commandLine":"C:\\\\Windows\\\\System32\\\\cmd.exe"}}}'
)

with open('tests/create_logs.py', 'w', newline='\n') as f:
    f.write(content)
