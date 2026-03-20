#!/bin/bash
cd /mnt/c/Users/Vimalatithyan/OneDrive/Desktop/Technieum-X
echo "Calling /crtsh-certs?domain=trutrip.co ..."
curl -s "http://localhost:8000/api/v1/subdomains/crtsh-certs?domain=trutrip.co" --max-time 90 > /tmp/crt_result.json 2>&1
STATUS=$?
if [ $STATUS -ne 0 ]; then
  echo "curl failed: $STATUS"
  cat /tmp/crt_result.json
  exit 1
fi
python3 << 'EOF'
import json, sys
with open('/tmp/crt_result.json') as f:
    raw = f.read()
try:
    d = json.loads(raw)
except:
    print("Not valid JSON. Raw (first 300 chars):", raw[:300])
    sys.exit(1)
print(f"TOTAL: {d['total']}")
print(f"VALID: {d['valid']}  EXPIRING: {d['expiring']}  EXPIRED: {d['expired']}")
if d['certs']:
    print(f"Newest cert: id={d['certs'][0]['id']}  cn={d['certs'][0]['common_name']}  status={d['certs'][0]['status']}")
    print(f"Oldest cert: id={d['certs'][-1]['id']}  cn={d['certs'][-1]['common_name']}")
else:
    print("Messages:", d.get('messages'))
EOF
