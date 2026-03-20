#!/bin/bash
# Nuclei diagnostic script
export PATH="$HOME/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

echo "=== ENVIRONMENT ==="
echo "HOME=$HOME"
echo "PATH=$PATH"
echo "USER=$(whoami)"
echo ""

echo "=== NUCLEI BINARY ==="
NUCLEI_BIN=$(command -v nuclei 2>/dev/null)
if [ -z "$NUCLEI_BIN" ]; then
    echo "nuclei NOT FOUND in PATH"
    echo "Checking ~/go/bin:"
    ls -la "$HOME/go/bin/nuclei" 2>/dev/null || echo "  NOT in ~/go/bin either"
    echo "Checking /usr/bin:"
    ls -la /usr/bin/nuclei 2>/dev/null || echo "  NOT in /usr/bin either"
    exit 1
fi
echo "Binary: $NUCLEI_BIN"
echo "Version: $(nuclei -version 2>&1)"
echo ""

echo "=== NUCLEI TEMPLATES ==="
TMPL_DIR=""
for d in "$HOME/nuclei-templates" "$HOME/.local/nuclei-templates" "/opt/nuclei-templates" "/usr/share/nuclei-templates" "$HOME/.config/nuclei/templates"; do
    if [ -d "$d" ]; then
        TMPL_DIR="$d"
        cnt=$(find "$d" -name "*.yaml" 2>/dev/null | wc -l)
        echo "FOUND: $d ($cnt templates)"
        break
    fi
done
if [ -z "$TMPL_DIR" ]; then
    echo "NO TEMPLATE DIR FOUND"
    echo "Attempting: nuclei -update-templates"
    nuclei -update-templates 2>&1 | tail -5
fi
echo ""

echo "=== NUCLEI CONFIG ==="
[ -f "$HOME/.config/nuclei/.nuclei-ignore" ] && echo "Ignore file exists" || echo "No ignore file"
[ -f "$HOME/.config/nuclei/config.yaml" ] && echo "Config file exists" && cat "$HOME/.config/nuclei/config.yaml" || echo "No config file"
echo ""

echo "=== TEST 1: Simple tech-detect scan ==="
echo "Target: https://fundsverifier.com"
echo "https://fundsverifier.com" | timeout 60 nuclei -silent -tags tech -rate-limit 100 2>&1
echo "Exit code: $?"
echo ""

echo "=== TEST 2: Nuclei with verbose + JSON ==="
echo "https://fundsverifier.com" | timeout 60 nuclei -json -tags tech -rate-limit 100 -stats 2>&1 | tail -30
echo "Exit code: $?"
echo ""

echo "=== TEST 3: Nuclei without tags (broad) ==="
echo "https://fundsverifier.com" | timeout 90 nuclei -silent -severity critical,high,medium -rate-limit 100 2>&1 | head -20
echo "Exit code: $?"
echo ""

echo "=== TEST 4: Nuclei basic connectivity ==="
echo "https://fundsverifier.com" | timeout 30 nuclei -silent -t "$TMPL_DIR/http/technologies/" -rate-limit 100 2>&1 | head -10
echo "Exit code: $?"
echo ""

echo "=== DONE ==="
