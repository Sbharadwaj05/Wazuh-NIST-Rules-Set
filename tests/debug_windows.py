import subprocess
import os

def main():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    log_path = os.path.join(repo_root, "tests", "sample-logs", "de-cm-09", "windows-audit-cleared", "trigger.log")
    
    with open(log_path, "r", encoding="utf-8") as f:
        log_data = f.read()
        
    print("Log content:")
    print(log_data)
    
    proc = subprocess.run(
        ["sudo", "/var/ossec/bin/wazuh-logtest"],
        input=log_data,
        text=True,
        capture_output=True
    )
    print("--- STDOUT ---")
    print(proc.stdout)
    print("--- STDERR ---")
    print(proc.stderr)

if __name__ == "__main__":
    main()
