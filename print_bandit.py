import json
with open('bandit_final.json', encoding='utf-8-sig') as f:
    text = f.read()
    data = json.loads(text[text.find('{'):])

for r in data.get('results', []):
    if r['issue_severity'] == 'MEDIUM':
        print(f"{r['filename']}:{r['line_number']} -> {r['test_id']}")
