import re

log_100037 = r'{"win":{"system":{"eventID":"4624","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"logonType":"9","logonProcessName":"seclogo","authenticationPackageName":"Negotiate"}}}'
pattern_100037 = r'(?i)LogonType.*9.*LogonProcessName.*seclogo.*AuthenticationPackageName.*Negotiate'
print('Match 100037:', bool(re.search(pattern_100037, log_100037)))

log_100027 = r'{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA"}}}'
pattern_100027 = r'(?i)(powershell|pwsh)\.exe.*(\-e(nc(oded(Command)?)?)?|\-e\s)'
print('Match 100027:', bool(re.search(pattern_100027, log_100027)))
