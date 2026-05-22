# NIST CSF 2.0 -> Wazuh Rule Mapping

| NIST CSF Control | Control Description | Rule ID(s) | MITRE Technique | Log Source |
|---|---|---|---|---|
| DE.CM-01 | Network is monitored for cybersecurity events | 100001, 100005, 100010, 100013 | T1110.001, T1048, T1021.002, T1071.004 | Syslog, Windows Event |
| DE.CM-03 | Personnel activity is monitored | 100002, 100003, 100006, 100011 | T1548.003, T1136.001, T1003.008, T1110.003 | Syslog, auditd |
| DE.CM-09 | Monitoring for unauthorized personnel/devices/software | 100004, 100009, 100015 | T1053.003, T1070.001, T1543.003 | Syslog, Windows Event |
| DE.AE-02 | Detected events are analyzed | 100007, 100010, 100012 | T1505.003, T1021.002, T1055 | Apache/Nginx, Windows Event |
| DE.AE-03 | Event data aggregated and correlated | 100005, 100008, 100015 | T1048, T1030, T1543.003 | Netflow, Syslog |
| PR.AA-01 | Identities and credentials managed | 100003 | T1136.001 | Syslog, Windows Event |
| PR.AA-05 | Access permissions managed | 100002, 100014 | T1548.003, T1222.002 | auditd, Syslog |
| PR.DS-01 | Data-at-rest is protected | 100004, 100006 | T1053.003, T1003.008 | auditd |
| PR.DS-02 | Protections against data leaks | 100008 | T1030 | Proxy logs, Netflow |
| RS.MA-02 | Notifications from detection systems investigated | 100001, 100007 | T1110.001, T1505.003 | Syslog, Apache/Nginx |
| RS.AN-08 | Impact of incidents understood | 100012 | T1055 | Windows Event |
| ID.RA-03 | Threats identified and documented | 100013 | T1071.004 | DNS logs |
