import re
log = r'{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA"}}}'
pattern = r'(?i)(powershell|pwsh)\.exe.*(\-e(nc(oded(Command)?)?)?|\-e\s)'
print('Match:', bool(re.search(pattern, log)))
