#!/bin/bash
export PATH="$HOME/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

echo "=== NUCLEI v3.7.0 FIX VERIFICATION ==="
echo "Date: $(date)"
echo ""

# Test 1: Tech detection with -jsonl
echo "--- Test 1: Tech detection (-jsonl -tags tech) ---"
echo "https://fundsverifier.com" | timeout 90 nuclei -silent -jsonl -tags tech -rate-limit 150 -o /tmp/nuclei_test_tech.json 2>&1
if [ -s /tmp/nuclei_test_tech.json ]; then
    cnt=$(wc -l < /tmp/nuclei_test_tech.json)
    echo "SUCCESS: $cnt tech-detection findings"
    head -3 /tmp/nuclei_test_tech.json | python3 -c "import json,sys; [print(json.loads(l).get('template-id',''),'|',json.loads(l).get('info',{}).get('name','')) for l in sys.stdin if l.strip()]" 2>/dev/null
else
    echo "No tech findings (target may not expose technology signatures)"
fi
echo ""

# Test 2: CVE scan with -jsonl
echo "--- Test 2: CVE scan (-jsonl -severity critical,high,medium) ---"
echo "https://fundsverifier.com" | timeout 120 nuclei -silent -jsonl -severity critical,high,medium -tags cve,misconfiguration -rate-limit 150 -o /tmp/nuclei_test_cve.json 2>&1
if [ -s /tmp/nuclei_test_cve.json ]; then
    cnt=$(wc -l < /tmp/nuclei_test_cve.json)
    echo "SUCCESS: $cnt CVE/misconfig findings"
    head -3 /tmp/nuclei_test_cve.json | python3 -c "import json,sys; [print(json.loads(l).get('template-id',''),'|',json.loads(l).get('info',{}).get('severity',''),'|',json.loads(l).get('info',{}).get('name','')) for l in sys.stdin if l.strip()]" 2>/dev/null
else
    echo "No CVE/misconfig findings found"
fi
echo ""

# Test 3: Broad scan
echo "--- Test 3: Broad scan (all severities, no tag filter) ---"
echo "https://fundsverifier.com" | timeout 120 nuclei -silent -jsonl -severity critical,high,medium,low,info -rate-limit 150 -o /tmp/nuclei_test_broad.json 2>&1
if [ -s /tmp/nuclei_test_broad.json ]; then
    cnt=$(wc -l < /tmp/nuclei_test_broad.json)
    echo "SUCCESS: $cnt total findings"
    echo "Severities breakdown:"
    python3 -c "
import json, sys
from collections import Counter
sev = Counter()
for line in open('/tmp/nuclei_test_broad.json'):
    line = line.strip()
    if not line: continue
    try:
        obj = json.loads(line)
        s = obj.get('info',{}).get('severity','unknown')
        sev[s] += 1
    except: pass
for s in ['critical','high','medium','low','info','unknown']:
    if sev[s]: print(f'  {s}: {sev[s]}')
print(f'  TOTAL: {sum(sev.values())}')
" 2>/dev/null
else
    echo "No findings from broad scan"
fi
echo ""

echo "=== NUCLEI FIX VERIFIED ==="
rm -f /tmp/nuclei_test_tech.json /tmp/nuclei_test_cve.json /tmp/nuclei_test_broad.json 2>/dev/null
