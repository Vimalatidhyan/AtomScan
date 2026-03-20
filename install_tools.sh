#!/usr/bin/env bash
# ==============================================================================
# Technieum — Install all tools and libraries required to run the full scan pipeline.
# Targets: Kali Linux, Debian, Ubuntu (apt-based).
# Usage: sudo ./install_tools.sh   (or run as root; apt requires elevated privileges)
# ==============================================================================

set -uo pipefail
# Note: set +e used instead of set -e to prevent optional tool install failures
# from aborting the entire script.  Critical sections check exit codes explicitly.
set +e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Platform check — this script targets Debian/Ubuntu/Kali
if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "[install] WARNING: macOS detected. This script is designed for Debian/Ubuntu/Kali Linux."
    echo "[install] apt-based installs will be skipped. Go/pip/npm tools will still be attempted."
fi

# Use sudo for apt if not root
APT_CMD="apt-get"
if [[ $EUID -ne 0 ]] && command -v sudo &>/dev/null; then
    APT_CMD="sudo apt-get"
fi

# ------------------------------------------------------------------------------
# All system packages used across modules 00–09
# ------------------------------------------------------------------------------
# Phase 0:  whois, python3
# Phase 1:  subfinder, amass, assetfinder, dnsx, httpx, asnmap, mapcidr,
#           curl, jq, whois, python3
# Phase 2:  nmap, rustscan, subjack, gitleaks, trufflehog, git-secrets,
#           netcat, python3, dnsx
# Phase 3:  gau, waybackurls, gospider, hakrawler, katana, ffuf, feroxbuster,
#           dirsearch, arjun, newman, cariddi, mantra, python3
# Phase 4:  nuclei, nikto, dalfox, sqlmap, wpscan, wapiti, skipfish, cmsmap,
#           testssl.sh, sslyze, retire.js, gowitness, python3, jq
# Phase 5:  curl, dig, host, jq, python3
# Phase 6:  curl, python3, jq
# Phase 7:  python3
# Phase 8:  testssl.sh, python3
# Phase 9:  python3
# General:  coreutils (timeout / gtimeout), git
# ------------------------------------------------------------------------------

APT_PACKAGES=(
    # ── Core system tools ──
    dnsutils              # dig, nslookup
    bind9-host            # host
    whois
    curl
    git
    jq
    coreutils             # timeout
    netcat-openbsd        # nc

    # ── Phase 1: Discovery ──
    subfinder
    amass
    nmap                  # also phase 2

    # ── Phase 2: Intel ──
    # rustscan (may only be on Kali repos)

    # ── Phase 3: Content ──
    feroxbuster
    dirsearch

    # ── Phase 4: Vuln ──
    nuclei
    nikto
    sqlmap
    wpscan
    wapiti
    skipfish
    sslyze
    testssl.sh

    # ── httpx: on Kali = httpx-toolkit ──
    httpx-toolkit
)

# Packages that might only exist in Kali repos — try individually
KALI_OPTIONAL_PACKAGES=(
    rustscan
    gau
    waybackurls
    gospider
    hakrawler
    katana
    dalfox
    subjack
    gitleaks
    trufflehog
    arjun
    assetfinder
    dnsx
    asnmap
    mapcidr
    ffuf
    cmsmap
)

echo "[install] Technieum full-pipeline dependency installer"
echo "[install] Script dir: $SCRIPT_DIR"
echo ""

# ------------------------------------------------------------------------------
# 1. APT (system tools)
# ------------------------------------------------------------------------------
if command -v apt-get &>/dev/null; then
    echo "[install] Updating apt cache..."
    $APT_CMD update -qq 2>/dev/null || true

    echo "[install] Installing core system packages..."
    if ! DEBIAN_FRONTEND=noninteractive $APT_CMD install -y \
        "${APT_PACKAGES[@]}" \
        python3 python3-pip python3-venv 2>/dev/null; then
        echo "[install] Some packages failed — trying essentials only..."
        DEBIAN_FRONTEND=noninteractive $APT_CMD install -y \
            dnsutils bind9-host whois curl git jq coreutils netcat-openbsd \
            nmap nuclei nikto sqlmap \
            python3 python3-pip python3-venv 2>/dev/null || true
    fi

    echo "[install] Trying Kali-optional packages (non-fatal)..."
    for pkg in "${KALI_OPTIONAL_PACKAGES[@]}"; do
        DEBIAN_FRONTEND=noninteractive $APT_CMD install -y "$pkg" 2>/dev/null || \
            echo "[install]   $pkg not in apt repos — will try Go/pip fallback"
    done
else
    echo "[install] WARNING: apt-get not found. Install packages manually."
fi

# ------------------------------------------------------------------------------
# 2. Go-based tools — fallback if not installed via apt
# ------------------------------------------------------------------------------
export PATH="${PATH:-}:${HOME}/go/bin:/usr/local/go/bin"

install_go_tool() {
    local cmd="$1"
    local pkg="$2"
    if ! command -v "$cmd" &>/dev/null; then
        echo "[install] Installing $cmd via Go..."
        go install -v "$pkg" 2>/dev/null && echo "[install]   $cmd installed" || \
            echo "[install]   WARN: $cmd install failed (Go not available or build error)"
    fi
}

if command -v go &>/dev/null; then
    echo "[install] Installing Go-based tools (fallback for missing apt packages)..."

    # Phase 1 tools
    install_go_tool subfinder  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    install_go_tool amass      "github.com/owasp-amass/amass/v4/...@master"
    install_go_tool assetfinder "github.com/tomnomnom/assetfinder@latest"
    install_go_tool dnsx       "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    install_go_tool httpx      "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    install_go_tool asnmap     "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    install_go_tool mapcidr    "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
    # ct-monitor: no stable public Go module — cert transparency handled by subfinder/amass/dnsx

    # Phase 2 tools
    install_go_tool nuclei     "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    install_go_tool subjack    "github.com/haccer/subjack@latest"
    install_go_tool subover    "github.com/Ice3man543/SubOver@latest"

    # Phase 3 tools
    install_go_tool gau        "github.com/lc/gau/v2/cmd/gau@latest"
    install_go_tool waybackurls "github.com/tomnomnom/waybackurls@latest"
    install_go_tool gospider   "github.com/jaeles-project/gospider@latest"
    install_go_tool hakrawler  "github.com/hakluke/hakrawler@latest"
    install_go_tool katana     "github.com/projectdiscovery/katana/cmd/katana@latest"
    install_go_tool ffuf       "github.com/ffuf/ffuf/v2@latest"
    install_go_tool cariddi    "github.com/edoardottt/cariddi/cmd/cariddi@latest"   # deep crawl + secret/endpoint/API-key extraction
    install_go_tool mantra     "github.com/Brosck/mantra@latest"                     # JS/HTML API key leak hunter

    # Phase 4 tools
    install_go_tool dalfox     "github.com/hahwul/dalfox/v2@latest"

    # GoWitness — web screenshot & technology fingerprinting
    install_go_tool gowitness  "github.com/sensepost/gowitness@latest"

    # Other tools
    install_go_tool dnsprober  "github.com/mrhenrike/dnsprober@latest"         # DNS bruteforcer
    install_go_tool subprober  "github.com/0xSojalSec/Subprober@latest"        # subdomain HTTP prober
else
    echo "[install] WARNING: Go not found — some tools require manual installation."
    echo "  Install Go from https://go.dev/dl/ and re-run this script."
fi

# ------------------------------------------------------------------------------
# 3. Pip-based tools — installed inside the virtualenv (section 4)
# Note: Kali Linux Python 3.13 uses PEP 668 (externally-managed-environment).
# All pip packages are installed into .venv below to avoid that restriction.
# ------------------------------------------------------------------------------

# Newman (Node.js)
if command -v npm &>/dev/null; then
    echo "[install] Installing newman via npm..."
    npm install -g newman 2>/dev/null || true
elif command -v npx &>/dev/null; then
    echo "[install] npm not found but npx available — newman will use npx at runtime"
fi

# retire.js (Node.js)
if command -v npm &>/dev/null; then
    echo "[install] Installing retire.js via npm..."
    npm install -g retire 2>/dev/null || true
fi

# Git tools
if command -v git &>/dev/null; then
    # git-secrets
    if ! command -v git-secrets &>/dev/null; then
        echo "[install] Installing git-secrets..."
        (cd /tmp && git clone https://github.com/awslabs/git-secrets.git 2>/dev/null && \
         cd git-secrets && make install 2>/dev/null) || echo "[install]   WARN: git-secrets install failed"
    fi
    # gitleaks
    if ! command -v gitleaks &>/dev/null && command -v go &>/dev/null; then
        install_go_tool gitleaks "github.com/gitleaks/gitleaks/v8@latest"
    fi
    # trufflehog
    if ! command -v trufflehog &>/dev/null; then
        echo "[install] Installing trufflehog..."
        pip3 install --user --quiet --break-system-packages trufflehog 2>/dev/null || \
        (command -v go &>/dev/null && go install github.com/trufflesecurity/trufflehog/v3@latest 2>/dev/null) || \
            echo "[install]   WARN: trufflehog install failed"
    fi
fi

# GoWitness (git clone fallback if Go install failed)
if ! command -v gowitness &>/dev/null; then
    echo "[install] Cloning GoWitness from GitHub..."
    if [ ! -d /opt/gowitness ]; then
        git clone --depth 1 https://github.com/sensepost/gowitness.git /opt/gowitness 2>/dev/null || true
    fi
    if [ -d /opt/gowitness ] && command -v go &>/dev/null; then
        echo "[install] Building GoWitness from source..."
        (cd /opt/gowitness && go build -o /usr/local/bin/gowitness . 2>/dev/null) || \
            echo "[install]   WARN: GoWitness build failed"
    fi
fi

# linkfinder / SecretFinder (Python tools — cloned to /opt)
if [ ! -d /opt/LinkFinder ]; then
    echo "[install] Cloning LinkFinder..."
    git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git /opt/LinkFinder 2>/dev/null || true
fi
if [ ! -d /opt/SecretFinder ]; then
    echo "[install] Cloning SecretFinder..."
    git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git /opt/SecretFinder 2>/dev/null || true
fi

# Feroxbuster binary (if not in apt)
if ! command -v feroxbuster &>/dev/null; then
    echo "[install] Installing feroxbuster..."
    if command -v cargo &>/dev/null; then
        cargo install feroxbuster 2>/dev/null || echo "[install]   WARN: feroxbuster cargo install failed"
    else
        echo "[install]   WARN: feroxbuster not found and cargo not available"
    fi
fi

# RustScan (Rust/Cargo or binary)
if ! command -v rustscan &>/dev/null; then
    echo "[install] Installing rustscan..."
    if command -v cargo &>/dev/null; then
        cargo install rustscan 2>/dev/null || echo "[install]   WARN: rustscan cargo install failed"
    else
        echo "[install]   WARN: rustscan not found and cargo not available"
    fi
fi

# testssl.sh (if not in apt)
if ! command -v testssl.sh &>/dev/null && ! command -v testssl &>/dev/null; then
    echo "[install] Installing testssl.sh..."
    if [ ! -d /opt/testssl.sh ]; then
        git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh 2>/dev/null || true
    fi
    [ -f /opt/testssl.sh/testssl.sh ] && ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh 2>/dev/null || true
fi

# wpscan (Ruby gem)
if ! command -v wpscan &>/dev/null; then
    echo "[install] Installing wpscan..."
    if command -v gem &>/dev/null; then
        gem install wpscan 2>/dev/null || echo "[install]   WARN: wpscan gem install failed"
    fi
fi

# ------------------------------------------------------------------------------
# 4. Python virtualenv and pip dependencies (requirements.txt + requirements-api.txt)
# ------------------------------------------------------------------------------
PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" &>/dev/null; then
    echo "[install] ERROR: $PYTHON not found. Install python3 and re-run."
    exit 1
fi

VENV_DIR="${VENV_DIR:-.venv}"
if [[ ! -d "$VENV_DIR" ]]; then
    echo "[install] Creating virtualenv at $VENV_DIR..."
    "$PYTHON" -m venv "$VENV_DIR" || {
        echo "[install] WARN: venv creation failed — trying with --without-pip..."
        "$PYTHON" -m venv --without-pip "$VENV_DIR" || true
    }
fi

# Resolve the venv pip binary (never embed flags in a variable — use run_pip() below)
_VENV_PIP=""
for _p in "$VENV_DIR/bin/pip" "$SCRIPT_DIR/$VENV_DIR/bin/pip"; do
    [[ -x "$_p" ]] && { _VENV_PIP="$_p"; break; }
done

# Bootstrap pip into venv if it was created --without-pip
if [[ -z "$_VENV_PIP" ]]; then
    _VP="$VENV_DIR/bin/python"
    [[ -x "$_VP" ]] || _VP="$SCRIPT_DIR/$VENV_DIR/bin/python"
    if [[ -x "$_VP" ]]; then
        echo "[install] Bootstrapping pip into $VENV_DIR via ensurepip..."
        "$_VP" -m ensurepip --upgrade 2>/dev/null || \
            curl -fsSL https://bootstrap.pypa.io/get-pip.py | "$_VP" 2>/dev/null || true
        [[ -x "$VENV_DIR/bin/pip" ]] && _VENV_PIP="$VENV_DIR/bin/pip"
    fi
fi

# run_pip: route through venv pip when available, fall back to system pip3
# Flags are passed as arguments — never embedded in a variable.
run_pip() {
    if [[ -n "$_VENV_PIP" ]]; then
        "$_VENV_PIP" "$@"
    else
        echo "[install] WARN: venv pip unavailable; using system pip3 --break-system-packages"
        pip3 --break-system-packages "$@" 2>/dev/null || true
    fi
}

echo "[install] Upgrading pip in $VENV_DIR..."
run_pip install --upgrade pip -q 2>/dev/null || true

# pip-based recon tools (arjun, dirsearch, sslyze, censys, shodan) into venv
echo "[install] Installing pip-based recon tools into venv..."
run_pip install -q \
    arjun \
    dirsearch \
    sslyze \
    censys \
    shodan \
    2>/dev/null || true

REQ_TXT="$SCRIPT_DIR/requirements.txt"
REQ_API="$SCRIPT_DIR/requirements-api.txt"
if [[ -f "$REQ_TXT" ]]; then
    echo "[install] Installing Python deps from requirements.txt..."
    run_pip install -r "$REQ_TXT" -q
fi
if [[ -f "$REQ_API" ]]; then
    echo "[install] Installing Python deps from requirements-api.txt..."
    run_pip install -r "$REQ_API" -q
fi

# ------------------------------------------------------------------------------
# 5. Harness + module scripts executable
# ------------------------------------------------------------------------------
RUN_SCAN="$SCRIPT_DIR/lib/run_scan.sh"
if [[ -f "$RUN_SCAN" ]]; then
    chmod +x "$RUN_SCAN"
    echo "[install] lib/run_scan.sh is executable."
fi
# Make all module scripts executable
chmod +x "$SCRIPT_DIR"/modules/*.sh 2>/dev/null || true
echo "[install] Module scripts in modules/ are executable."

# ------------------------------------------------------------------------------
# 6. Report versions (all tools across modules 00–09)
# ------------------------------------------------------------------------------
echo ""
echo "[install] ══════════════════════════════════════════════════════════════"
echo "[install] Installed tool versions (used across modules 00–09):"
echo "[install] ══════════════════════════════════════════════════════════════"

ALL_TOOLS=(
    # Core / DNS
    dig nslookup host whois curl jq git timeout python3
    # Phase 1
    subfinder amass assetfinder dnsx httpx asnmap mapcidr
    subdominator dnsbruter dnsprober
    cloud_enum s3scanner goblob gcpbucketbrute
    # Phase 2
    nmap nc rustscan subprober shodan shodanx dorker censys
    subjack subover gitleaks trufflehog git-secrets gh githunt
    # Phase 3
    gau waybackurls spideyx gospider hakrawler katana
    ffuf feroxbuster dirsearch linkfinder jsscanner
    newman kr arjun cariddi mantra
    # Phase 4
    nuclei dalfox sqlmap nikto wpscan wapiti skipfish cmsmap
    testssl.sh testssl sslyze retire gowitness
    # Phase 5–9
    # (mostly Python modules — no extra binaries)
)

for cmd in "${ALL_TOOLS[@]}"; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" --version 2>/dev/null | head -1 || true)
        [[ -z "$ver" ]] && ver=$("$cmd" -V 2>/dev/null | head -1 || true)
        [[ -z "$ver" ]] && ver=$("$cmd" -v 2>/dev/null | head -1 || true)
        [[ -z "$ver" ]] && ver="(installed — version unknown)"
        printf "  %-20s %s\n" "$cmd" "$ver"
    else
        printf "  %-20s %s\n" "$cmd" "NOT FOUND"
    fi
done

echo ""
echo "  Python: $("$PYTHON" --version 2>&1)"
if [[ -n "${_VENV_PIP:-}" ]]; then
    echo "  pip:    $("$_VENV_PIP" --version 2>&1 | head -1)"
else
    echo "  pip:    (venv pip not available)"
fi
echo "  venv:   $VENV_DIR"
echo ""
echo "[install] Done. Run the app with: ./start.sh"
echo "          Or run a single scan:   ./lib/run_scan.sh 1 example.com full"
