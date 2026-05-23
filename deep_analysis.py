import glob
import re
import os

failed_ids = [
    "100026", "100027", "100028", "100029", "100030", "100031", "100032",
    "100033", "100034", "100035", "100036", "100037", "100038", "100039",
    "100040", "100041", "100044", "100047", "100048", "100050", "100052",
    "100053", "100054"
]

passed_ids = [
    "100018", "100002", "100003", "100004", "100005", "100006", "100007",
    "100008", "100009", "100010", "100016", "100011", "100012", "100013",
    "100014", "100015", "100019", "100020", "100021", "100022", "100023",
    "100024", "100025", "100042", "100043", "100045", "100046", "100049",
    "100051"
]

files = glob.glob('rules/**/*.xml', recursive=True)

def extract_rule(rule_id):
    for f in files:
        with open(f, 'r', encoding='utf-8') as file:
            content = file.read()
            # Match <rule id="X"...</rule>
            pattern = r'<rule id="' + rule_id + r'".*?</rule>'
            match = re.search(pattern, content, re.DOTALL)
            if match:
                return f, match.group(0)
    return None, None

print("=== DEEP ANALYSIS OF FAILED RULES ===")
for rid in failed_ids:
    f, rule_xml = extract_rule(rid)
    if rule_xml:
        # Extract <regex> or <field>
        match_logic = re.findall(r'<(regex|field)[^>]*>.*?</\1>', rule_xml)
        if_sid = re.search(r'<if_sid>(.*?)</if_sid>', rule_xml)
        print(f"Rule: {rid}")
        print(f"If_SID: {if_sid.group(1) if if_sid else 'None'}")
        for logic in match_logic:
            # find actual tag content
            full_tag = re.search(r'<(regex|field)[^>]*>.*?</\1>', rule_xml).group(0)
            print(f"  {full_tag}")
        print("")

print("=== DEEP ANALYSIS OF PASSED RULES (SAMPLE) ===")
for rid in ["100042", "100043", "100049", "100051"]:
    f, rule_xml = extract_rule(rid)
    if rule_xml:
        match_logic = re.findall(r'<(regex|field)[^>]*>.*?</\1>', rule_xml)
        if_sid = re.search(r'<if_sid>(.*?)</if_sid>', rule_xml)
        print(f"Rule: {rid}")
        print(f"If_SID: {if_sid.group(1) if if_sid else 'None'}")
        for logic in match_logic:
            full_tag = re.search(r'<(regex|field)[^>]*>.*?</\1>', rule_xml).group(0)
            print(f"  {full_tag}")
        print("")
