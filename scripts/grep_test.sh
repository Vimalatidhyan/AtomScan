#!/bin/bash
export PATH="$HOME/go/bin:$HOME/.pdtm/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

echo "=== Test mantra grep pattern ==="
echo "https://fundsverifier.com/_next/static/chunks/23ec41c2aa165413.js" | timeout 20 mantra > /tmp/mt.txt 2>/dev/null
echo "Total lines: $(wc -l < /tmp/mt.txt)"

echo "grep1 (^\[+\]): $(grep -c '^\[+\]' /tmp/mt.txt 2>/dev/null || echo 0)"
echo "grep2 (\[+\]): $(grep -c '\[+\]' /tmp/mt.txt 2>/dev/null || echo 0)"
echo "grep3 (\\\[\\+\\]): $(grep -c '\[+\]' /tmp/mt.txt 2>/dev/null || echo 0)"
echo "grep4 (fixed \\[\\+\\]): $(grep -cF '[+]' /tmp/mt.txt 2>/dev/null || echo 0)"

echo ""
echo "--- File content ---"
cat /tmp/mt.txt

echo ""
echo "--- Hex of [+] line ---"
grep -F '[+]' /tmp/mt.txt | xxd | head -5

echo "=== DONE ==="
