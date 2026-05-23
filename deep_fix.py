import os
import glob
import re

files = glob.glob('rules/**/*.xml', recursive=True)

# Helper function to replace rule content
def replace_rule_content(rule_id, new_content):
    for f in files:
        with open(f, 'r', encoding='utf-8') as file:
            content = file.read()
        
        pattern = r'(<rule id="' + rule_id + r'".*?>\s*)(.*?)(^\s*</rule>)'
        match = re.search(pattern, content, re.DOTALL | re.MULTILINE)
        if match:
            updated_rule = match.group(1) + new_content + match.group(3)
            content = content.replace(match.group(0), updated_rule)
            with open(f, 'w', encoding='utf-8', newline='\n') as file:
                file.write(content)
            print(f"Updated {rule_id} in {f}")
            return True
    return False

# Category 1: Auditd logic flaws
# Rule 100026: change if_sid 100004 to 80700
replace_rule_content("100026", """<if_sid>80700</if_sid>
    <regex type="pcre2">path=(/var/spool/cron/(crontabs/)?root|/etc/crontab)</regex>
    <description>Root crontab modification detected (Persistence)</description>
    <mitre>
      <id>T1053.003</id>
    </mitre>
    <group>DE.CM-09, PR.AC-04</group>
""")

# Rule 100041: change uid=[^0]\b to uid=(?!0\b)\d+\b
replace_rule_content("100041", """<if_sid>80700</if_sid>
    <regex type="pcre2">(?i)path=\/etc\/(shadow|passwd)\s.*uid=(?!0\b)\d+\b.*exe="(?!(\/usr\/bin\/(sudo|passwd|su|login|sshd)))</regex>
    <description>Linux shadow/passwd file read by non-root process (Credential Access)</description>
    <mitre>
      <id>T1003.008</id>
    </mitre>
    <group>PR.AA-05, DE.AE-02</group>
""")


# Category 2: JSON full_log regex flaws
json_replacements = {
    "100027": """<decoded_as>json</decoded_as>
    <field name="win.system.providerName">Microsoft-Windows-Sysmon</field>
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(powershell|pwsh)\.exe.*(\-e(nc(oded(Command)?)?)?|\-e\s)</field>
    <description>PowerShell encoded command execution (Defense Evasion)</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
    <group>DE.AE-02</group>
""",
    "100028": """<decoded_as>json</decoded_as>
    <field name="win.system.providerName">Microsoft-Windows-Sysmon</field>
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(Net\.WebClient|Invoke-WebRequest|DownloadString|DownloadFile|IEX|Invoke-Expression)</field>
    <description>PowerShell web download string executed (Execution/C2)</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
    <group>DE.AE-02</group>
""",
    "100029": """<decoded_as>json</decoded_as>
    <field name="win.system.providerName">Microsoft-Windows-Sysmon</field>
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)schtasks\.exe.*\/create</field>
    <description>Scheduled task creation detected via Sysmon (Persistence)</description>
    <mitre>
      <id>T1053.005</id>
    </mitre>
    <group>DE.AE-02</group>
""",
    "100030": """<decoded_as>json</decoded_as>
    <field name="win.system.providerName">Microsoft-Windows-Sysmon</field>
    <field name="win.system.eventID">^12$|^13$|^14$</field>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)(Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run|Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce)</field>
    <description>Registry Run/RunOnce key modification (Persistence)</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
    <group>DE.AE-02</group>
""",
    "100031": """<decoded_as>json</decoded_as>
    <field name="win.system.providerName">Microsoft-Windows-Sysmon</field>
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(vssadmin|wmic).*(delete\s+shadows|shadowcopy\s+delete)</field>
    <description>Volume Shadow Copy deletion detected (Impact)</description>
    <mitre>
      <id>T1490</id>
    </mitre>
    <group>DE.AE-02</group>
""",
    "100032": """<decoded_as>json</decoded_as>
    <field name="win.system.providerName">Microsoft-Windows-Security-Auditing</field>
    <field name="win.system.eventID">^4732$|^4728$</field>
    <field name="win.eventdata.targetUserName" type="pcre2">(?i)(Administrators|Domain\s+Admins|Enterprise\s+Admins)</field>
    <description>User added to privileged administrative group (Privilege Escalation)</description>
    <mitre>
      <id>T1078</id>
    </mitre>
    <group>PR.AA-01, PR.AC-04</group>
""",
    "100033": """<decoded_as>json</decoded_as>
    <field name="win.system.providerName">Microsoft-Windows-Sysmon</field>
    <field name="win.system.eventID">^12$|^13$|^14$</field>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)(System\\\\CurrentControlSet\\\\Control\\\\Terminal\sServer\\\\fDenyTSConnections|System\\\\CurrentControlSet\\\\Control\\\\Terminal\sServer\\\\WinStations\\\\RDP-Tcp\\\\PortNumber)</field>
    <description>RDP registry configuration modification (Defense Evasion/Lateral Movement)</description>
    <mitre>
      <id>T1112</id>
    </mitre>
    <group>PR.AA-05</group>
""",
    "100034": """<decoded_as>json</decoded_as>
    <field name="win.system.providerName">Microsoft-Windows-Sysmon</field>
    <field name="win.system.eventID">^19$|^20$|^21$</field>
    <field name="win.eventdata.filterName" type="pcre2">(?i)(__EventFilter|__EventConsumer|__FilterToConsumerBinding)</field>
    <description>WMI event filter/consumer activity (Persistence)</description>
    <mitre>
      <id>T1546.003</id>
    </mitre>
    <group>DE.AE-02</group>
""",
    "100035": """<decoded_as>json</decoded_as>
    <field name="win.system.providerName">Microsoft-Windows-Sysmon</field>
    <field name="win.system.eventID">^10$</field>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe</field>
    <field name="win.eventdata.grantedAccess" type="pcre2">(?i)(0x1010|0x1410|0x143a|0x1f0fff|0x1fffff)</field>
    <description>LSASS memory access indicating credential dumping (Credential Access)</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
    <group>DE.AE-02</group>
""",
    "100036": """<decoded_as>json</decoded_as>
    <field name="win.system.providerName">Microsoft-Windows-Sysmon</field>
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(sekurlsa|lsadump|kerberos::|crypto::|privilege::debug|mimikatz)</field>
    <description>Mimikatz execution footprint detected (Credential Access)</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
    <group>DE.AE-02</group>
""",
    "100037": """<decoded_as>json</decoded_as>
    <field name="win.system.providerName">Microsoft-Windows-Security-Auditing</field>
    <field name="win.system.eventID">^4624$</field>
    <field name="win.eventdata.logonType">9</field>
    <field name="win.eventdata.logonProcessName" type="pcre2">(?i)seclogo</field>
    <field name="win.eventdata.authenticationPackageName" type="pcre2">(?i)Negotiate</field>
    <description>Pass-the-Hash (PtH) logon indicators (Lateral Movement)</description>
    <mitre>
      <id>T1550.002</id>
    </mitre>
    <group>DE.CM-01, PR.AC-04</group>
""",
    "100038": """<decoded_as>json</decoded_as>
    <field name="win.system.providerName">Microsoft-Windows-Security-Auditing</field>
    <field name="win.system.eventID">^4662$</field>
    <field name="win.eventdata.properties" type="pcre2">(?i)(1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-ceed-11d0-929a-00c04fd92fcb)</field>
    <field name="win.eventdata.accessMask">0x100</field>
    <description>DCSync Active Directory replication requested (Credential Access)</description>
    <mitre>
      <id>T1003.006</id>
    </mitre>
    <group>ID.RA-03, PR.AC-04</group>
""",
    "100039": """<decoded_as>json</decoded_as>
    <field name="win.system.providerName">Microsoft-Windows-Security-Auditing</field>
    <field name="win.system.eventID">^4769$</field>
    <field name="win.eventdata.ticketOptions">0x40810000</field>
    <field name="win.eventdata.ticketEncryptionType">0x17</field>
    <description>Kerberoasting TGS request downgrade detected (Credential Access)</description>
    <mitre>
      <id>T1558.003</id>
    </mitre>
    <group>ID.RA-03, PR.AC-04</group>
""",
    "100040": """<decoded_as>json</decoded_as>
    <field name="win.system.providerName">Microsoft-Windows-Security-Auditing</field>
    <field name="win.system.eventID">^4740$</field>
    <description>Helper: Account Lockout Event 4740</description>
""",
    "100044": """<decoded_as>json</decoded_as>
    <field name="win.system.providerName">Microsoft-Windows-Sysmon</field>
    <field name="win.system.eventID">^22$</field>
    <field name="win.eventdata.queryName" type="pcre2">(?i)[A-Za-z0-9\-\.]{40,}\.(com|net|org|io|xyz)</field>
    <description>Suspiciously long DNS query indicating potential DNS Tunneling (C2)</description>
    <mitre>
      <id>T1071.004</id>
    </mitre>
    <group>DE.AE-03, RS.AN-01</group>
""",
    "100047": """<decoded_as>json</decoded_as>
    <field name="win.system.providerName">Microsoft-Windows-Sysmon</field>
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)certutil\.exe.*(\-urlcache|\-split|\-f|http(s)?:\/\/)</field>
    <description>Certutil used to download remote payload (C2/Defense Evasion)</description>
    <mitre>
      <id>T1105</id>
    </mitre>
    <group>DE.AE-02, DE.CM-01</group>
""",
    "100048": """<decoded_as>json</decoded_as>
    <field name="win.system.providerName">Microsoft-Windows-Sysmon</field>
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(regsvr32\.exe|rundll32\.exe).*(http(s)?:\/\/|scrobj\.dll|\/i:)</field>
    <description>Regsvr32/Rundll32 remote script execution (Defense Evasion)</description>
    <mitre>
      <id>T1218.010</id>
    </mitre>
    <group>DE.AE-02, DE.CM-01</group>
""",
    "100050": """<decoded_as>json</decoded_as>
    <field name="win.system.eventID">^1002$|^1003$</field>
    <field name="win.eventdata.message" type="pcre2">(?i)(veeam|rsync|bacula|windows\s+backup|wbadmin).*(failed|error|terminated\s+unexpectedly|could\s+not\s+complete|fatal)</field>
    <description>Critical backup failure detected (Recovery Impact)</description>
    <mitre>
      <id>T1490</id>
    </mitre>
    <group>RC.RP-01</group>
""",
    "100054": """<decoded_as>json</decoded_as>
    <field name="win.system.providerName">Microsoft-Windows-Sysmon</field>
    <field name="win.system.eventID">^3$</field>
    <field name="win.eventdata.destinationIsIpv6">false</field>
    <description>Helper: Sysmon Network Connection IPv4</description>
"""
}

# Wait! Rule 100050 payload: Dec 10 14:30:00 server veeam: Backup job failed terminated unexpectedly
# Wait! 100050 log is NOT json!
# It is a syslog payload!
# In create_logs.py for 100050:
# 'Dec 10 14:30:00 server veeam: Backup job failed terminated unexpectedly\n'
# Wait! If 100050 is syslog, then replacing it with `<decoded_as>json</decoded_as>` is WRONG!

for k, v in json_replacements.items():
    if k != "100050":
        replace_rule_content(k, v)

replace_rule_content('100050', '''<decoded_as>syslog</decoded_as>
    <regex type="pcre2">(?i)(veeam|rsync|bacula|windows\s+backup|wbadmin).*(failed|error|terminated\s+unexpectedly|could\s+not\s+complete|fatal)</regex>
    <description>Critical backup failure detected (Recovery Impact)</description>
    <mitre>
      <id>T1490</id>
    </mitre>
    <group>RC.RP-01</group>
''')
