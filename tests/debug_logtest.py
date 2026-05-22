import subprocess
import sys
import os

def test(log_path):
    print(f"=== Debugging {log_path} ===")
    if not os.path.exists(log_path):
        print(f"Error: File {log_path} does not exist!")
        return
        
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            log_data = f.read()
        
        print(f"Log content ({len(log_data.splitlines())} lines):")
        for line in log_data.splitlines():
            print(f"  > {line}")
        print()
        
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
        print("==============================")
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_log = os.path.join(repo_root, "tests", "sample-logs", "de-cm-01", "ssh-bruteforce", "trigger.log")
    
    if len(sys.argv) > 1:
        test(sys.argv[1])
    else:
        test(default_log)
