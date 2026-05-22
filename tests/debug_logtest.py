import subprocess
import sys
import os
import glob

def find_matched_rule(log_path):
    if not os.path.exists(log_path):
        return None
        
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            log_data = f.read()
        
        proc = subprocess.run(
            ["sudo", "/var/ossec/bin/wazuh-logtest"],
            input=log_data,
            text=True,
            capture_output=True
        )
        
        # Parse the output to find the matched rule ID(s)
        # We can find all lines like "id: 'XXXX'"
        rule_ids = []
        descriptions = []
        decoders = []
        
        for line in proc.stderr.splitlines():
            if "id: '" in line:
                rule_ids.append(line.split("'")[1])
            elif "description: '" in line:
                descriptions.append(line.split("'")[1])
            elif "name: '" in line or "parent: '" in line:
                decoders.append(line.split("'")[1])
                
        # Return the last matched rule (since logtest outputs sequentially for each line)
        if rule_ids:
            return {
                "rule_id": rule_ids[-1],
                "description": descriptions[-1] if descriptions else "No description",
                "decoder": decoders[-1] if decoders else "Unknown",
                "all_rule_ids": rule_ids
            }
    except Exception as e:
        print("Error processing", log_path, ":", e)
    return None

def main():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sample_logs_dir = os.path.join(repo_root, "tests", "sample-logs")
    
    print(f"=== Scanning all sample log triggers in {sample_logs_dir} ===")
    
    # Walk through the folders to find all trigger.log files
    trigger_logs = glob.glob(os.path.join(sample_logs_dir, "**", "trigger.log"), recursive=True)
    trigger_logs.sort()
    
    for log_path in trigger_logs:
        rel_path = os.path.relpath(log_path, sample_logs_dir)
        res = find_matched_rule(log_path)
        if res:
            print(f"Log: {rel_path}")
            print(f"  Matched Rule ID: {res['rule_id']}")
            print(f"  Description:     {res['description']}")
            print(f"  Decoder:         {res['decoder']}")
            print(f"  All Rule IDs:    {res['all_rule_ids']}")
        else:
            print(f"Log: {rel_path} -> Failed to match any rule or wazuh-logtest failed.")
        print("-" * 50)

if __name__ == "__main__":
    main()
