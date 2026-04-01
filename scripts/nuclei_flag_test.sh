#!/bin/bash
export PATH="$HOME/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

echo "=== NUCLEI FLAG CHECK ==="
echo "Version: $(nuclei -version 2>&1 | head -1)"
echo ""

# Check which JSON flag works
echo "Testing -json flag:"
echo "https://example.com" | timeout 15 nuclei -tags tech -json -silent 2>&1 | head -5
echo "Exit: $?"
echo ""

echo "Testing -jsonl flag:"
echo "https://example.com" | timeout 15 nuclei -tags tech -jsonl -silent 2>&1 | head -5
echo "Exit: $?"
echo ""

echo "Testing -j flag:"
echo "https://example.com" | timeout 15 nuclei -tags tech -j -silent 2>&1 | head -5
echo "Exit: $?"
echo ""

echo "Testing -je (json-export) flag:"
echo "https://example.com" | timeout 15 nuclei -tags tech -silent -je /tmp/nuclei_test_export.json 2>&1 | head -5
echo "Exit: $?"
[ -f /tmp/nuclei_test_export.json ] && echo "Export file created: $(wc -c < /tmp/nuclei_test_export.json) bytes" && cat /tmp/nuclei_test_export.json | head -5
echo ""

echo "Testing -jsonl-export flag:"
echo "https://example.com" | timeout 15 nuclei -tags tech -silent -jsonl-export /tmp/nuclei_test_jsonl.json 2>&1 | head -5
echo "Exit: $?"
[ -f /tmp/nuclei_test_jsonl.json ] && echo "JSONL export file: $(wc -c < /tmp/nuclei_test_jsonl.json) bytes"
echo ""

# Check nuclei help for output flags
echo "=== NUCLEI OUTPUT FLAGS ==="
nuclei -h 2>&1 | grep -iE 'json|output|export|silent' | head -20
echo ""

echo "=== QUICK REAL SCAN (no -json, just stdout) ==="
echo "https://fundsverifier.com" | timeout 60 nuclei -tags tech -silent -rate-limit 150 2>&1 | head -20
echo "Exit: $?"
echo ""

echo "=== QUICK SCAN with -jsonl ==="
echo "https://fundsverifier.com" | timeout 60 nuclei -tags tech -silent -jsonl -rate-limit 150 2>&1 | head -20
echo "Exit: $?"
echo ""

echo "=== DONE ==="
