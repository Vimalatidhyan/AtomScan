#!/bin/bash
# Quick verification of cariddi -s and mantra fixes
export PATH="$HOME/go/bin:$HOME/.pdtm/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

echo "========================================"
echo "  SECRET SCAN FIX VERIFICATION"
echo "========================================"

OUTDIR="/tmp/verify_secrets"
rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

# Test URLs (fundsverifier + known JS files with secrets)
cat > "$OUTDIR/urls.txt" <<'EOF'
https://fundsverifier.com
https://fundsverifier.com/_next/static/chunks/23ec41c2aa165413.js
https://fundsverifier.com/_next/static/chunks/08dcfc3b15383cd6.js
https://fundsverifier.com/manifest.json
EOF

echo ""
echo "--- cariddi -s (raw output) ---"
cat "$OUTDIR/urls.txt" | timeout 45 cariddi -s > "$OUTDIR/raw.txt" 2>/dev/null
RAW=$(wc -l < "$OUTDIR/raw.txt")
echo "  Raw output: $RAW lines (crawled URLs + any secrets)"

echo "--- Extracting [+] secrets ---"
grep '^\[+\]' "$OUTDIR/raw.txt" > "$OUTDIR/secrets_only.txt" 2>/dev/null || true
SEC=$(wc -l < "$OUTDIR/secrets_only.txt")
echo "  Clean secrets: $SEC [+] findings"
if [ "$SEC" -gt 0 ]; then
    echo "  Findings:"
    cat "$OUTDIR/secrets_only.txt"
fi

echo ""
echo "--- mantra on ALL URLs ---"
cat "$OUTDIR/urls.txt" | timeout 30 mantra > "$OUTDIR/mantra.txt" 2>/dev/null
MRAW=$(wc -l < "$OUTDIR/mantra.txt")
grep '^\[+\]' "$OUTDIR/mantra.txt" > "$OUTDIR/mantra_secrets.txt" 2>/dev/null || true
MSEC=$(wc -l < "$OUTDIR/mantra_secrets.txt")
echo "  Total output: $MRAW lines"
echo "  Secrets found: $MSEC"
if [ "$MSEC" -gt 0 ]; then
    echo "  Findings:"
    cat "$OUTDIR/mantra_secrets.txt"
fi

echo ""
echo "========================================"
echo "RESULT: cariddi=$SEC secrets, mantra=$MSEC secrets"
echo "========================================"
