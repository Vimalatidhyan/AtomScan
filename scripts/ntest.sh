#!/bin/bash
export PATH="$HOME/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

echo "=== nuclei -h output flags ==="
nuclei -h 2>&1 | grep -iE 'json|output|export' | head -15
echo ""

echo "=== Test 1: -json flag ==="
echo "https://example.com" | timeout 20 nuclei -tags tech -json -silent 2>&1
echo "RC=$?"
echo ""

echo "=== Test 2: -jsonl flag ==="
echo "https://example.com" | timeout 20 nuclei -tags tech -jsonl -silent 2>&1
echo "RC=$?"
echo ""

echo "DONE"
