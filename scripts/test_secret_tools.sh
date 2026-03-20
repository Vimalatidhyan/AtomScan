#!/bin/bash
export PATH="$HOME/go/bin:$HOME/.pdtm/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

echo "=== Testing cariddi -s ==="
echo "cariddi version: $(cariddi -version 2>&1 || echo 'no -version flag')"
echo "cariddi path: $(which cariddi 2>/dev/null)"

echo ""
echo "=== Test 1: cariddi -s on example.com ==="
echo "https://example.com" | timeout 30 cariddi -s > /tmp/cariddi_t1.txt 2>/tmp/cariddi_t1.err
echo "Exit: $?"
echo "Stdout lines: $(wc -l < /tmp/cariddi_t1.txt)"
echo "Stderr lines: $(wc -l < /tmp/cariddi_t1.err)"
echo "--- stdout ---"
head -20 /tmp/cariddi_t1.txt
echo "--- stderr (first 10) ---"
head -10 /tmp/cariddi_t1.err
echo ""

echo "=== Test 2: cariddi -s on fundsverifier.com ==="
echo "https://fundsverifier.com" | timeout 45 cariddi -s > /tmp/cariddi_t2.txt 2>/tmp/cariddi_t2.err
echo "Exit: $?"
echo "Stdout lines: $(wc -l < /tmp/cariddi_t2.txt)"
echo "[+] lines: $(grep -c '^\[+\]' /tmp/cariddi_t2.txt || echo 0)"
echo "--- stdout sample ---"
head -20 /tmp/cariddi_t2.txt
echo "--- [+] entries ---"
grep '^\[+\]' /tmp/cariddi_t2.txt | head -10

echo ""
echo "=== Test 3: mantra on fundsverifier.com JS ==="
echo "https://fundsverifier.com/_next/static/chunks/23ec41c2aa165413.js" | timeout 20 mantra > /tmp/mantra_t1.txt 2>/tmp/mantra_t1.err
echo "Exit: $?"
echo "Stdout lines: $(wc -l < /tmp/mantra_t1.txt)"
echo "--- stdout ---"
cat /tmp/mantra_t1.txt
echo "--- stderr ---"
head -5 /tmp/mantra_t1.err

echo ""
echo "=== DONE ==="
