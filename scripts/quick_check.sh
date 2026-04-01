#!/bin/bash
# Quick tool check with proper PATH
export PATH="$HOME/go/bin:/usr/local/go/bin:$PATH"

echo "=== TECHNIEUM-X CRITICAL TOOL CHECK ==="
echo "PATH includes: $HOME/go/bin"
echo ""

OK=0; MISS=0

for t in nuclei cariddi mantra dalfox katana gau skipfish gitleaks trufflehog sqlmap nikto feroxbuster ffuf httpx gowitness waybackurls subfinder nmap testssl wpscan arjun dirsearch corsy; do
    if command -v "$t" &>/dev/null; then
        loc=$(command -v "$t")
        echo "[OK]      $t  ->  $loc"
        ((OK++))
    else
        echo "[MISSING] $t"
        ((MISS++))
    fi
done

echo ""
echo "────────────────────────────────────"
echo "RESULT: $OK OK  |  $MISS MISSING"
echo "────────────────────────────────────"

echo ""
echo "=== CARIDDI v1.4.5 FLAG CHECK ==="
if command -v cariddi &>/dev/null; then
    _ch=$(cariddi -h 2>&1)
    for flag in "-s" "-e" "-err" "-info" "-ext" "-json" "-plain" "-rua" "-ie" "-intensive" "-c" "-t" "-d"; do
        if echo "$_ch" | grep -q -- "$flag"; then
            printf "  %-12s SUPPORTED\n" "$flag"
        else
            printf "  %-12s NOT FOUND\n" "$flag"
        fi
    done
fi

echo ""
echo "=== KEY VERSIONS ==="
echo "nuclei:     $(nuclei -version 2>&1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
echo "cariddi:    $(cariddi -version 2>&1 | head -1)"
echo "dalfox:     $(dalfox version 2>&1 | head -1)"
echo "katana:     $(katana -version 2>&1 | head -1)"
echo "gau:        $(gau --version 2>&1 | head -1)"
echo "mantra:     $(command -v mantra) (stdin pipe tool)"
echo "gitleaks:   $(gitleaks version 2>&1 | head -1)"
echo "trufflehog: $(trufflehog --version 2>&1 | head -1)"
echo "skipfish:   $(command -v skipfish)"
echo "sqlmap:     $(sqlmap --version 2>&1 | head -1)"

echo ""
echo "=== NUCLEI TEMPLATES ==="
for d in "$HOME/nuclei-templates" "$HOME/.local/nuclei-templates" "/opt/nuclei-templates" "$HOME/.config/nuclei/templates"; do
    if [ -d "$d" ]; then
        cnt=$(find "$d" -name "*.yaml" 2>/dev/null | wc -l)
        echo "Templates: $d ($cnt templates)"
        break
    fi
done

echo ""
echo "=== SKIPFISH DICTIONARY ==="
for dict in "/usr/share/skipfish/dictionaries/minimal.wl" "/usr/share/skipfish/dictionaries/complete.wl"; do
    [ -f "$dict" ] && echo "Dictionary: $dict FOUND"
done

echo ""
if [ "$MISS" -eq 0 ]; then
    echo "*** ALL TOOLS READY — YOU CAN INITIATE A SCAN ***"
else
    echo "*** $MISS tools missing (non-critical ones can be skipped) ***"
fi
