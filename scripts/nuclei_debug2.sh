#!/bin/bash
export PATH="$HOME/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

echo "=== NETWORK CHECK ==="
curl -sI https://fundsverifier.com 2>&1 | head -5
echo "Exit: $?"
echo ""

echo "=== NUCLEI HEALTH CHECK ==="
nuclei -health-check 2>&1 | tail -10
echo ""

echo "=== TEST: nuclei -stats (shows progress) ==="
echo "https://fundsverifier.com" | timeout 120 nuclei -tags tech -rate-limit 100 -stats -stats-interval 5 -verbose 2>&1 | tail -40
echo "Exit: $?"
echo ""

echo "=== TEST: nuclei with -t (explicit template dir) ==="
TMPL=""
for d in "$HOME/nuclei-templates" "$HOME/.config/nuclei/templates"; do
    if [ -d "$d/http/technologies" ]; then
        TMPL="$d/http/technologies"
        break
    elif [ -d "$d/technologies" ]; then
        TMPL="$d/technologies"
        break
    fi
done
echo "Template dir: $TMPL"
if [ -n "$TMPL" ]; then
    echo "Templates in dir: $(find "$TMPL" -name '*.yaml' | wc -l)"
    echo ""
    echo "Running with explicit -t $TMPL ..."
    echo "https://fundsverifier.com" | timeout 90 nuclei -t "$TMPL" -rate-limit 100 -stats -stats-interval 5 2>&1 | tail -30
    echo "Exit: $?"
fi
echo ""

echo "=== TEST: nuclei CVE scan ==="
echo "https://fundsverifier.com" | timeout 90 nuclei -tags cve -severity critical,high -rate-limit 100 -stats -stats-interval 5 2>&1 | tail -20
echo "Exit: $?"
echo ""

echo "=== TEST: nuclei NO FILTER (all templates) ==="
echo "https://fundsverifier.com" | timeout 120 nuclei -severity critical,high,medium,low,info -rate-limit 150 -stats -stats-interval 10 -silent 2>&1 | head -30
echo "Exit: $?"
echo ""

echo "=== DONE ==="
