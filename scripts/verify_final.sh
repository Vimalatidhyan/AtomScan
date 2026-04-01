#!/bin/bash
# Final verification: simulates the exact pipeline from 03_content.sh
export PATH="$HOME/go/bin:$HOME/.pdtm/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

echo "========================================"
echo "  FINAL SECRET SCAN FIX VERIFICATION"
echo "========================================"

OUTDIR="/tmp/final_verify"
rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

# Test URLs (fundsverifier + known JS files)
cat > "$OUTDIR/urls.txt" <<'EOF'
https://fundsverifier.com
https://fundsverifier.com/_next/static/chunks/23ec41c2aa165413.js
https://fundsverifier.com/_next/static/chunks/08dcfc3b15383cd6.js
https://fundsverifier.com/manifest.json
EOF

echo ""
echo "--- Step 1: cat urls.txt | cariddi -s ---"
cat "$OUTDIR/urls.txt" | timeout 45 cariddi -s > "$OUTDIR/cariddi_raw.txt" 2>/dev/null
RAW=$(wc -l < "$OUTDIR/cariddi_raw.txt")
echo "  Raw output: $RAW lines"

echo "--- Step 2: grep -F '[+]' (extract secrets) ---"
grep -F '[+]' "$OUTDIR/cariddi_raw.txt" > "$OUTDIR/cariddi_secrets.txt" 2>/dev/null || true
SEC=$(wc -l < "$OUTDIR/cariddi_secrets.txt")
echo "  Extracted secrets: $SEC"
if [ "$SEC" -gt 0 ]; then
    cat "$OUTDIR/cariddi_secrets.txt"
fi

echo ""
echo "--- Step 3: cat urls.txt | mantra ---"
cat "$OUTDIR/urls.txt" | timeout 30 mantra > "$OUTDIR/mantra_raw.txt" 2>/dev/null
MRAW=$(wc -l < "$OUTDIR/mantra_raw.txt")
echo "  Raw output: $MRAW lines"

echo "--- Step 4: grep -F '[+]' (extract mantra secrets) ---"
grep -F '[+]' "$OUTDIR/mantra_raw.txt" > "$OUTDIR/mantra_secrets.txt" 2>/dev/null || true
MSEC=$(wc -l < "$OUTDIR/mantra_secrets.txt")
echo "  Extracted secrets: $MSEC"
if [ "$MSEC" -gt 0 ]; then
    cat "$OUTDIR/mantra_secrets.txt"
fi

echo ""
echo "========================================"
echo "  RESULTS"
echo "  cariddi -s: $RAW crawled URLs, $SEC secrets extracted"
echo "  mantra:     $MRAW output lines, $MSEC secrets extracted"
echo "========================================"
