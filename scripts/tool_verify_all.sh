#!/bin/bash
# Comprehensive tool verification for Technieum-X
# Checks all critical scanning tools and their flags

echo "====== TECHNIEUM-X TOOL VERIFICATION ======"
echo "Date: $(date)"
echo ""

OK=0
MISS=0
WARN=0

check() {
    local name="$1"
    if command -v "$name" &>/dev/null; then
        echo "[OK] $name: $(command -v "$name")"
        ((OK++))
        return 0
    else
        echo "[MISSING] $name"
        ((MISS++))
        return 1
    fi
}

echo "────────────────────────────────────────────"
echo "  PHASE 0-1: DISCOVERY & RECON"
echo "────────────────────────────────────────────"
check "nmap"
check "subfinder"
check "amass"
check "httpx"
check "massdns"
check "asnmap"
check "dnsrecon"

echo ""
echo "────────────────────────────────────────────"
echo "  PHASE 2: INTEL / OSINT"
echo "────────────────────────────────────────────"
check "whois"
check "theHarvester"
check "shodan"

echo ""
echo "────────────────────────────────────────────"
echo "  PHASE 3: CONTENT DISCOVERY / CRAWLING"
echo "────────────────────────────────────────────"
check "katana"
check "gau"
check "waybackurls"
check "cariddi"
check "mantra"
check "ffuf"
check "feroxbuster"
check "dirsearch"
check "arjun"

echo ""
echo "  Cariddi flag verification (v1.4.5):"
if command -v cariddi &>/dev/null; then
    _ch=$(cariddi -h 2>&1)
    for flag in "-s" "-e" "-err" "-info" "-ext" "-json" "-plain" "-rua" "-ie" "-intensive" "-c" "-t" "-d"; do
        if echo "$_ch" | grep -q -- "$flag"; then
            echo "    $flag: SUPPORTED"
        else
            echo "    $flag: not found"
            ((WARN++))
        fi
    done
fi

echo ""
echo "  Mantra verification:"
if command -v mantra &>/dev/null; then
    echo "    mantra binary: $(command -v mantra)"
    echo "    Usage: cat js_urls.txt | mantra"
    echo "    test: echo 'https://example.com/test.js' | timeout 10 mantra 2>/dev/null | head -5"
fi

echo ""
echo "────────────────────────────────────────────"
echo "  PHASE 3 SECRET SCANNING (after JS crawl)"
echo "────────────────────────────────────────────"
check "gitleaks"
check "trufflehog"

echo ""
echo "  Gitleaks verification:"
if command -v gitleaks &>/dev/null; then
    _glv=$(gitleaks version 2>/dev/null)
    echo "    Version: $_glv"
    if echo "$_glv" | grep -qE '^[89]|^[1-9][0-9]'; then
        echo "    v8+ mode: gitleaks detect --no-git --source <dir>"
    else
        echo "    v7 mode: gitleaks --path <dir> --no-git"
    fi
fi

echo ""
echo "  TruffleHog verification:"
if command -v trufflehog &>/dev/null; then
    _thv=$(trufflehog --version 2>&1 | head -1)
    echo "    Version: $_thv"
    if trufflehog --help 2>&1 | grep -q 'filesystem'; then
        echo "    filesystem mode: SUPPORTED"
    else
        echo "    filesystem mode: NOT SUPPORTED (fallback to per-file scan)"
        ((WARN++))
    fi
fi

echo ""
echo "────────────────────────────────────────────"
echo "  PHASE 4: VULNERABILITY SCANNING"
echo "────────────────────────────────────────────"
check "nuclei"
check "dalfox"
check "sqlmap"
check "nikto"
check "skipfish"
check "corsy" || [ -f "/opt/Corsy/corsy.py" ] && echo "    [OK] corsy.py at /opt/Corsy/corsy.py"
check "wpscan"
check "gowitness"
check "testssl.sh" || check "testssl"

echo ""
echo "  Nuclei verification:"
if command -v nuclei &>/dev/null; then
    _nv=$(nuclei -version 2>&1 | head -1)
    echo "    Version: $_nv"
    # Check template dirs
    for _tdir in "$HOME/nuclei-templates" "$HOME/.local/nuclei-templates" "/opt/nuclei-templates" "/usr/share/nuclei-templates" "$HOME/.config/nuclei/templates"; do
        if [ -d "$_tdir" ]; then
            _tcount=$(find "$_tdir" -name "*.yaml" 2>/dev/null | wc -l)
            echo "    Templates: $_tdir ($_tcount templates)"
            break
        fi
    done
fi

echo ""
echo "  Skipfish verification:"
if command -v skipfish &>/dev/null; then
    if [ -f "/usr/share/skipfish/dictionaries/minimal.wl" ]; then
        echo "    Dictionary: minimal.wl FOUND"
    elif [ -f "/usr/share/skipfish/dictionaries/complete.wl" ]; then
        echo "    Dictionary: complete.wl FOUND"
    else
        echo "    Dictionary: NOT FOUND"
        ((WARN++))
    fi
fi

echo ""
echo "  Dalfox verification:"
if command -v dalfox &>/dev/null; then
    _dv=$(dalfox version 2>&1 | head -1)
    echo "    Version: $_dv"
    echo "    Pipe mode: cat urls.txt | dalfox pipe --silence"
fi

echo ""
echo "────────────────────────────────────────────"
echo "  PHASE 5-9: SSL/THREAT-INTEL/COMPLIANCE"
echo "────────────────────────────────────────────"
check "jq"
check "python3"
check "curl"
check "dig"

echo ""
echo "════════════════════════════════════════════"
echo "  RESULT: OK=$OK  |  MISSING=$MISS  |  WARNINGS=$WARN"
echo "════════════════════════════════════════════"

if [ "$MISS" -eq 0 ]; then
    echo ""
    echo "  ✓ ALL CRITICAL TOOLS INSTALLED — READY TO SCAN"
else
    echo ""
    echo "  ✗ $MISS tools missing — install them before scanning"
fi
