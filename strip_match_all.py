import glob

files = glob.glob('rules/**/*.xml', recursive=True)
for f in files:
    with open(f, 'r', encoding='utf-8') as file:
        content = file.read()
    
    if 'match="all"' in content:
        content = content.replace(' match="all"', '')
        with open(f, 'w', encoding='utf-8', newline='\n') as file:
            file.write(content)
        print(f"Removed match='all' from {f}")
