import os
import shutil
import re
import subprocess

def main():
    repo_root = os.path.dirname(os.path.abspath(__file__))
    rules_source = os.path.join(repo_root, "rules")
    lists_source = os.path.join(repo_root, "lists")
    decoders_source = os.path.join(repo_root, "decoders")

    wazuh_root = "/var/ossec"
    wazuh_rules_dir = os.path.join(wazuh_root, "etc", "rules")
    wazuh_lists_dir = os.path.join(wazuh_root, "etc", "lists")
    wazuh_decoders_dir = os.path.join(wazuh_root, "etc", "decoders")
    ossec_conf_path = os.path.join(wazuh_root, "etc", "ossec.conf")

    print("[*] Starting deployment. Repository root:", repo_root)

    os.makedirs(wazuh_rules_dir, exist_ok=True)
    os.makedirs(wazuh_lists_dir, exist_ok=True)
    os.makedirs(wazuh_decoders_dir, exist_ok=True)

    # STEP 1: Clean old custom rule deployments
    print("\n[*] STEP 1: Cleaning old rule deployments from /var/ossec/etc/rules/...")
    if os.path.exists(wazuh_rules_dir):
        for file in os.listdir(wazuh_rules_dir):
            file_path = os.path.join(wazuh_rules_dir, file)
            if os.path.isfile(file_path) and file.endswith(".xml"):
                os.remove(file_path)
                print(f"  [!] Removed old rule file: {file}")
    print("[+] STEP 1 complete.")

    # STEP 2: Deploy and sanitize rules
    print("\n[*] STEP 2: Deploying rules...")
    rules_count = 0
    for root, dirs, files in os.walk(rules_source):
        for file in files:
            if file.endswith(".xml"):
                src_file = os.path.join(root, file)
                dst_file = os.path.join(wazuh_rules_dir, file)
                with open(src_file, "r", encoding="utf-8") as f:
                    content = f.read()
                
                # Strip out any <category>...</category> tags entirely on-the-fly
                clean_content = re.sub(r"\s*<category>.*?</category>", "", content)
                
                with open(dst_file, "w", encoding="utf-8", newline="\n") as f:
                    f.write(clean_content)
                print(f"  [+] Deployed (clean): {file}")
                rules_count += 1
    print(f"[+] STEP 2 complete. {rules_count} rules deployed.")

    # STEP 3: Deploy CDB lists
    print("\n[*] STEP 3: Deploying CDB lists...")
    if os.path.exists(lists_source):
        for file in os.listdir(lists_source):
            src_file = os.path.join(lists_source, file)
            dst_file = os.path.join(wazuh_lists_dir, file)
            if os.path.isfile(src_file):
                shutil.copy2(src_file, dst_file)
                print(f"  [+] Deployed list: {file}")
    print("[+] STEP 3 complete.")

    # STEP 3B: Deploy custom decoders
    print("\n[*] STEP 3B: Deploying custom decoders...")
    if os.path.exists(decoders_source):
        for file in os.listdir(decoders_source):
            src_file = os.path.join(decoders_source, file)
            dst_file = os.path.join(wazuh_decoders_dir, file)
            if os.path.isfile(src_file) and file.endswith(".xml"):
                shutil.copy2(src_file, dst_file)
                print(f"  [+] Deployed custom decoder: {file}")
    print("[+] STEP 3B complete.")

    # STEP 4: Patch ossec.conf
    print("\n[*] STEP 4: Patching ossec.conf (default rules + custom NIST rules)...")
    if os.path.exists(ossec_conf_path):
        with open(ossec_conf_path, "r", encoding="utf-8") as f:
            conf_content = f.read()

        ruleset_replacement = """<ruleset>
    <!-- Default Wazuh ruleset (REQUIRED for decoder categories) -->
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>

    <!-- Custom NIST CSF v2.0 ruleset -->
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
    <list>etc/lists/rare-ports</list>
    <list>etc/lists/c2-domains</list>
  </ruleset>"""

        pattern = r"(?i)<ruleset>.*?</ruleset>"
        if re.search(pattern, conf_content, flags=re.DOTALL):
            conf_content = re.sub(pattern, ruleset_replacement, conf_content, flags=re.DOTALL)
            with open(ossec_conf_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(conf_content)
            print("[+] Patched ossec.conf.")
            print("  [OK] Default decoders")
            print("  [OK] Default rules")
            print("  [OK] Custom rules")
            print("  [OK] rare-ports list")
            print("  [OK] c2-domains list")
            print("[+] STEP 4 complete. ossec.conf verified.")
            print("\n--- Deployed <ruleset> block ---")
            print(ruleset_replacement)
            print("--- End of <ruleset> block ---")
        else:
            print("[-] WARNING: Could not find <ruleset> block in ossec.conf!")
    else:
        print("[-] WARNING: /var/ossec/etc/ossec.conf not found!")

    # STEP 5: Apply system permissions
    print("\n[*] STEP 5: Applying permissions...")
    try:
        for w_dir in [wazuh_rules_dir, wazuh_lists_dir, wazuh_decoders_dir]:
            os.chmod(w_dir, 0o770)
            shutil.chown(w_dir, user="wazuh", group="wazuh")
            for root, dirs, files in os.walk(w_dir):
                for d in dirs:
                    dir_path = os.path.join(root, d)
                    os.chmod(dir_path, 0o770)
                    shutil.chown(dir_path, user="wazuh", group="wazuh")
                for f in files:
                    file_path = os.path.join(root, f)
                    os.chmod(file_path, 0o660)
                    shutil.chown(file_path, user="wazuh", group="wazuh")
        print("[+] STEP 5 complete.")
    except Exception as e:
        print("[-] Error applying permissions:", e)

    # STEP 5B: Compile CDB Lists
    print("\n[*] STEP 5B: Compiling CDB Lists...")
    try:
        makelist_path = None
        for name in ["wazuh-makelist", "ossec-makelist"]:
            path = os.path.join(wazuh_root, "bin", name)
            if os.path.exists(path):
                makelist_path = path
                break
        if makelist_path:
            subprocess.run([makelist_path], check=True)
            print(f"[+] STEP 5B complete. CDB lists compiled successfully using {os.path.basename(makelist_path)}.")
        else:
            print("[-] Error compiling CDB lists: neither wazuh-makelist nor ossec-makelist was found in /var/ossec/bin.")
    except Exception as e:
        print("[-] Error compiling CDB lists:", e)

    # STEP 6: Run syntax validation check
    print("\n[*] STEP 6: Running Wazuh syntax check...")
    result = subprocess.run([os.path.join(wazuh_root, "bin", "wazuh-analysisd"), "-t"], capture_output=True, text=True)
    
    if "ERROR" in result.stderr or "CRITICAL" in result.stderr:
        print(result.stderr)
        print("[-] FAILED with error(s) during syntax check.")
    else:
        print(result.stdout)
        print("[+] All checks passed flawlessly! Ready to restart wazuh-manager.")

if __name__ == "__main__":
    main()
