#!/bin/bash
set -e
cd /mnt/c/Users/Vimalatithyan/OneDrive/Desktop/Technieum-X

echo "Testing crt.sh cert endpoint (this may take 15-30s)..."
curl -s "http://localhost:8000/api/v1/subdomains/crtsh-certs?domain=trutrip.co" --max-time 60 -o /tmp/crt_test.json

python3 - << 'PYEOF'
import json
with open('/tmp/crt_test.json') as f:
    d = json.load(f)
print(f"total: {d['total']} | valid: {d['valid']} | expiring: {d['expiring']} | expired: {d['expired']}")
if d['certs']:
    c = d['certs'][0]
    print(f"First cert: id={c['id']} cn={c['common_name']} status={c['status']}")
    print(f"Last cert:  id={d['certs'][-1]['id']} cn={d['certs'][-1]['common_name']}")
else:
    print("No certs returned:", d.get('messages'))
PYEOF
