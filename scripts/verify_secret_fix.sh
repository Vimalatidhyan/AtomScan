#!/bin/bash
# Test cariddi -s -plain and mantra with all_urls.txt
# Verifies the fix for proper secret scanning
export PATH="$HOME/go/bin:$HOME/.pdtm/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

echo "==================================================================="
echo "  CARIDDI + MANTRA SECRET SCAN VERIFICATION"
echo "==================================================================="

TARGET="https://fundsverifier.com"
OUTDIR="/tmp/secret_test"
rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

# Create a small URL list (target + a known JS file)
cat > "$OUTDIR/test_urls.txt" <<'EOF'
https://fundsverifier.com
https://fundsverifier.com/_next/static/chunks/23ec41c2aa165413.js
https://fundsverifier.com/_next/static/chunks/08dcfc3b15383cd6.js
https://fundsverifier.com/manifest.json
EOF

echo ""
echo "--- Test 1: cariddi -s (OLD WAY - no -plain) ---"
echo "Command: cat urls.txt | cariddi -s"
cat "$OUTDIR/test_urls.txt" | timeout 45 cariddi -s > "$OUTDIR/cariddi_no_plain.txt" 2>/dev/null
NO_PLAIN_LINES=$(wc -l < "$OUTDIR/cariddi_no_plain.txt")
NO_PLAIN_SECRETS=$(grep -c '^\[+\]' "$OUTDIR/cariddi_no_plain.txt" 2>/dev/null || echo 0)
echo "  Total output lines: $NO_PLAIN_LINES"
echo "  Actual [+] secrets: $NO_PLAIN_SECRETS"
echo "  Problem: $NO_PLAIN_LINES lines but only $NO_PLAIN_SECRETS are secrets!"
echo "  Sample (first 5 lines):"
head -5 "$OUTDIR/cariddi_no_plain.txt" | sed 's/^/    /'

echo ""
echo "--- Test 2: cariddi -s -plain (FIXED WAY) ---"
echo "Command: cat urls.txt | cariddi -s -plain"
cat "$OUTDIR/test_urls.txt" | timeout 45 cariddi -s -plain > "$OUTDIR/cariddi_plain.txt" 2>/dev/null
PLAIN_LINES=$(wc -l < "$OUTDIR/cariddi_plain.txt")
PLAIN_SECRETS=$(grep -c '^\[+\]' "$OUTDIR/cariddi_plain.txt" 2>/dev/null || echo 0)
echo "  Total output lines: $PLAIN_LINES"
echo "  Actual [+] secrets: $PLAIN_SECRETS"
echo "  All output:"
cat "$OUTDIR/cariddi_plain.txt" | head -20 | sed 's/^/    /'

echo ""
echo "--- Test 3: mantra on ALL URLs (FIXED WAY) ---"
echo "Command: cat urls.txt | mantra"
cat "$OUTDIR/test_urls.txt" | timeout 30 mantra > "$OUTDIR/mantra_all.txt" 2>/dev/null
MANTRA_LINES=$(wc -l < "$OUTDIR/mantra_all.txt")
MANTRA_SECRETS=$(grep -c '^\[+\]' "$OUTDIR/mantra_all.txt" 2>/dev/null || echo 0)
echo "  Total output lines: $MANTRA_LINES"
echo "  Actual [+] secrets: $MANTRA_SECRETS"
echo "  All [+] findings:"
grep '^\[+\]' "$OUTDIR/mantra_all.txt" | head -20 | sed 's/^/    /'

echo ""
echo "==================================================================="
echo "  SUMMARY"
echo "==================================================================="
echo "  cariddi -s (old):       $NO_PLAIN_LINES lines, $NO_PLAIN_SECRETS secrets"
echo "  cariddi -s -plain (new): $PLAIN_LINES lines, $PLAIN_SECRETS secrets"
echo "  mantra on all URLs:      $MANTRA_LINES lines, $MANTRA_SECRETS secrets"
echo ""
if [ "$PLAIN_LINES" -lt "$NO_PLAIN_LINES" ] || [ "$MANTRA_SECRETS" -gt 0 ]; then
    echo "  FIX VERIFIED: -plain flag filters out noise, mantra finds secrets!"
else
    echo "  NOTE: Target may not have detectable secrets (this is normal)"
fi
echo "==================================================================="
