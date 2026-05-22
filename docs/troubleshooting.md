# Deep Dive Troubleshooting & Lessons Learned

While building and rigorously testing this NIST CSF detection pack, we encountered several advanced edge cases within the Wazuh rules and decoder engine. We are documenting them here to save other detection engineers hours of debugging.

## 1. The "No Decoder Matched" Trap (Decoder Shadowing)

**The Problem:**
While testing generic proxy syslog events (e.g., `Dec 10 14:28:01 webserver01 proxy: method=POST url=https://evil-exfil.com/upload bytes=150000000`), our rules chained to `<decoded_as>syslog</decoded_as>` or `<if_sid>1002</if_sid>` were failing to fire silently.

**The Discovery:**
When Wazuh successfully extracts a header during Phase 1 pre-decoding (identifying `program_name: proxy`), but fails to find a specific Phase 2 XML decoder explicitly designed for that `program_name`, it assigns the log an empty internal decoder name (outputting `No decoder matched`). 

Because the log lacks a designated decoder, the rules engine bypasses it entirely. It does **not** fall back to the built-in `syslog` decoder!

**The Solution:**
We resolved this by creating a dedicated custom decoder strictly matching the program name:
```xml
<decoder name="proxy">
  <program_name>^proxy</program_name>
</decoder>
```
Once Phase 2 assigns the log to the `proxy` decoder, we map our rule to `<decoded_as>proxy</decoded_as>`.

> [!WARNING]
> **Never shadow the built-in syslog decoder.** We initially attempted to create a catch-all `syslog` custom decoder. This "shadowed" the built-in Wazuh decoders, causing standard system logs (like Apache and Sshd) to fail parsing.

---

## 2. Rule Correlation Caveats (The Level 0 Invisible Rule)

**The Problem:**
Our Windows Logon Spray correlation rule (`100011`), which triggers when 5 logon failures occur from the same IP within 300 seconds, was not aggregating events properly using the `<same_field>win.eventdata.ipAddress</same_field>` correlation tag.

**The Discovery:**
The correlation tag `<if_matched_sid>100016</if_matched_sid>` relies on tracking the base rule (`100016: Windows Logon Failure`). However, we initially set rule `100016` to `level="0"`.

In Wazuh, **level 0 rules are discarded instantly**. They are not loaded into the active correlation memory state table, meaning child rules using `<if_matched_sid>` can never trigger.

**The Solution:**
Base rules required for time-series correlation must be at least **level 1**. We elevated the base rule to `level="3"` to ensure events were stored in memory long enough for the frequency tracker to evaluate them.

---

## 3. Windows Telemetry `<decoded_as>` Discrepancies

**The Problem:**
When testing Windows Security Events locally using a plaintext string of the Event Viewer XML payload, the rules would evaluate correctly. However, in production, they failed entirely.

**The Discovery:**
Wazuh agents deployed on Windows endpoints process Windows Event Channels natively into a highly structured JSON format internally before hitting the rules engine. 

**The Solution:**
Windows Event Channel rules **must** use `<decoded_as>json</decoded_as>` as their base requirement. Ensure you are targeting JSON fields dynamically (e.g., `win.eventdata.ipAddress`) rather than using standard syslog `<regex>` strings.

---

## 4. Wazuh Syntax Quirks (Multiple `<match>` Tags)

**The Problem:**
Our Sudo Privilege Escalation rule initially used the following logic:
```xml
<match>USER=root</match>
<match>COMMAND=</match>
```

**The Discovery:**
The Wazuh `ossec-analysisd` engine does **not** support multiple `<match>` tags. Only the last `<match>` tag is evaluated; preceding tags are ignored or cause parsing errors during compilation.

**The Solution:**
If you need to evaluate multiple string sequences, you must combine them into a single `<regex>` tag or use rule-chaining (parent/child hierarchy). We resolved this by chaining a child rule that verified `USER=root` after the parent verified `COMMAND=`.
