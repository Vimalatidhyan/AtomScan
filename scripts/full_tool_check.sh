#!/bin/bash
# Full tool check for all phases
set +e

check_tool() {
    local name="$1"
    local cmd="${2:-$1}"
    if command -v "$cmd" &>/dev/null; then
        local ver
        ver=$(timeout 5 "$cmd" --version 2>&1 | head -1 | head -c 80)
        [ -z "$ver" ] && ver=$(timeout 5 "$cmd" -version 2>&1 | head -1 | head -c 80)
        [ -z "$ver" ] && ver="(installed)"
        echo "[OK]   $name -> $ver"
    else
        echo "[MISS] $name -> NOT INSTALLED"
    fi
}

check_tool_exec() {
    local name="$1"
    local cmd="${2:-$1}"
    if command -v "$cmd" &>/dev/null; then
        if timeout 10 "$cmd" --help </dev/null &>/dev/null || timeout 10 "$cmd" -h </dev/null &>/dev/null; then
            echo "[OK]   $name -> executes OK"
        else
            echo "[WARN] $name -> installed but execution issue"
        fi
    else
        echo "[MISS] $name -> NOT INSTALLED"
    fi
}

echo "================================================================"
echo "  TECHNIEUM FULL TOOL AUDIT — $(date)"
echo "================================================================"
echo ""

echo "┌──────────────────────────────────────────────────────────────┐"
echo "│  PHASE 0: PRE-SCAN                                         │"
echo "└──────────────────────────────────────────────────────────────┘"
check_tool "dig" "dig"
check_tool "host" "host"

echo ""
echo "┌──────────────────────────────────────────────────────────────┐"
echo "│  PHASE 1: DISCOVERY & ENUMERATION                          │"
echo "└──────────────────────────────────────────────────────────────┘"
check_tool "whois"
check_tool "subfinder"
check_tool "assetfinder"
check_tool "subdominator"
check_tool "sublist3r"
check_tool "dnsbruter"
check_tool "dnsprobe"
check_tool "dnsx"
check_tool "httpx"
check_tool "asnmap"
check_tool "mapcidr"
check_tool "cloud_enum"
check_tool "s3scanner"
check_tool "goblob"
check_tool "gcpbucketbrute" "gcpbucketbrute"
check_tool "GCPBucketBrute" "GCPBucketBrute"

echo ""
echo "┌──────────────────────────────────────────────────────────────┐"
echo "│  PHASE 2: INTELLIGENCE GATHERING                           │"
echo "└──────────────────────────────────────────────────────────────┘"
check_tool "nmap"
check_tool "masscan"
check_tool "naabu"
check_tool "subprober"
check_tool "subjack"
check_tool "subover"
check_tool "gitleaks"
check_tool "trufflehog"
check_tool "git-secrets"
check_tool "gh" "gh"

echo ""
echo "┌──────────────────────────────────────────────────────────────┐"
echo "│  PHASE 3: CONTENT DISCOVERY & CRAWLING                     │"
echo "└──────────────────────────────────────────────────────────────┘"
check_tool "gau"
check_tool "gospider"
check_tool "katana"
check_tool "waybackurls"
check_tool "hakrawler"
check_tool "spideyx"
check_tool "cariddi"
check_tool "mantra"
check_tool "ffuf"
check_tool "feroxbuster"
check_tool "dirsearch"
check_tool "linkfinder"
check_tool "secretfinder"
check_tool "arjun"
check_tool "kiterunner" "kr"
check_tool "newman"

echo ""
echo "┌──────────────────────────────────────────────────────────────┐"
echo "│  PHASE 4: VULNERABILITY SCANNING                           │"
echo "└──────────────────────────────────────────────────────────────┘"
check_tool "nuclei"
check_tool "dalfox"
check_tool "sqlmap"
check_tool "corsy"
check_tool "nikto"
check_tool "wpscan"
check_tool "skipfish"
check_tool "cmsmap"
check_tool "retire" "retire"
check_tool "testssl.sh" "testssl.sh"
check_tool "sslyze"
check_tool "gowitness"
check_tool "wapiti"

echo ""
echo "┌──────────────────────────────────────────────────────────────┐"
echo "│  PHASE 5-9: ADVANCED ANALYSIS                              │"
echo "└──────────────────────────────────────────────────────────────┘"
check_tool "python3"
check_tool "jq"
check_tool "curl"
check_tool "wget"
check_tool "git"

echo ""
echo "================================================================"
echo "  SPECIAL INTEGRATION CHECKS"
echo "================================================================"

# Nuclei templates
echo ""
echo "--- Nuclei Templates ---"
_found=false
for d in "$HOME/nuclei-templates" "$HOME/.local/nuclei-templates" "/opt/nuclei-templates" "/usr/share/nuclei-templates" "$HOME/.config/nuclei/templates"; do
    if [ -d "$d" ]; then
        count=$(find "$d" -name '*.yaml' 2>/dev/null | wc -l)
        echo "[OK]   Nuclei templates at $d ($count templates)"
        _found=true
        break
    fi
done
[ "$_found" = "false" ] && echo "[MISS] Nuclei templates not found anywhere"

# Nuclei JSONL output (v3.7+ uses -jsonl, not -json)
echo ""
echo "--- Nuclei JSONL Support ---"
if command -v nuclei &>/dev/null; then
    if timeout 10 nuclei -h 2>&1 | grep -qiE '\-j,|\-jsonl'; then
        echo "[OK]   Nuclei supports JSONL output (-jsonl flag)"
    else
        echo "[WARN] Nuclei -jsonl flag not detected in help"
    fi
fi

# Skipfish dictionary
echo ""
echo "--- Skipfish Dictionary ---"
if [ -f "/usr/share/skipfish/dictionaries/minimal.wl" ]; then
    echo "[OK]   Skipfish minimal dictionary present"
elif [ -f "/usr/share/skipfish/dictionaries/complete.wl" ]; then
    echo "[OK]   Skipfish complete dictionary present"
else
    echo "[MISS] Skipfish dictionary not found"
fi

# Skipfish execution test
echo ""
echo "--- Skipfish Execution ---"
if command -v skipfish &>/dev/null; then
    if skipfish -h 2>&1 | grep -qi 'usage\|skipfish'; then
        echo "[OK]   Skipfish help works"
    else
        echo "[WARN] Skipfish exists but help command failed"
    fi
fi

# Gitleaks --no-git mode
echo ""
echo "--- Gitleaks --no-git Mode ---"
if command -v gitleaks &>/dev/null; then
    if gitleaks detect --help 2>&1 | grep -q 'no-git'; then
        echo "[OK]   Gitleaks supports --no-git (for web content scanning)"
    else
        echo "[WARN] Gitleaks --no-git not found (older version?)"
    fi
fi

# TruffleHog filesystem mode
echo ""
echo "--- TruffleHog Filesystem Mode ---"
if command -v trufflehog &>/dev/null; then
    if trufflehog --help 2>&1 | grep -q 'filesystem'; then
        echo "[OK]   TruffleHog supports filesystem mode (for web content scanning)"
    else
        echo "[WARN] TruffleHog filesystem mode not found (v2?)"
    fi
fi

# Subjack fingerprints
echo ""
echo "--- Subjack Fingerprints ---"
if [ -f "/usr/share/subjack/fingerprints.json" ]; then
    echo "[OK]   Subjack fingerprints present"
else
    echo "[MISS] Subjack fingerprints missing"
fi

# Wordlists
echo ""
echo "--- Wordlists ---"
if [ -d "/usr/share/seclists" ]; then
    echo "[OK]   SecLists present at /usr/share/seclists"
elif [ -d "/usr/share/wordlists" ]; then
    echo "[OK]   Wordlists present at /usr/share/wordlists"
else
    echo "[MISS] No wordlist directory found"
fi

if [ -f "/usr/share/wordlists/dirb/common.txt" ]; then
    echo "[OK]   dirb/common.txt wordlist present"
else
    echo "[MISS] dirb/common.txt missing"
fi

# Python3 modules needed
echo ""
echo "--- Python3 Modules ---"
for mod in json subprocess requests urllib3 dns; do
    if python3 -c "import $mod" 2>/dev/null; then
        echo "[OK]   Python module: $mod"
    else
        echo "[MISS] Python module: $mod"
    fi
done

echo ""
echo "================================================================"
echo "  SUMMARY"
echo "================================================================"
echo ""
echo "Report written at: $(date)"
echo "================================================================"
