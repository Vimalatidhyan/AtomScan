#!/usr/bin/env bash
# ==============================================================================
# Technieum — Install all tools and libraries required to run the full scan pipeline.
# Targets: Kali Linux, Debian, Ubuntu (apt-based).
# Usage: sudo ./install_tools.sh   (or run as root)
# ==============================================================================

# FIX: Remove -u (unbound var) and -e (exit on error) — use explicit checks instead
set -o pipefail
set +e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colour helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GRN}[OK]${NC}    $*"; }
warn() { echo -e "${YLW}[WARN]${NC}  $*"; }
err()  { echo -e "${RED}[ERR]${NC}   $*"; }
info() { echo -e "[INFO]  $*"; }

# ── Platform check ─────────────────────────────────────────────────────────────
OS="$(uname -s)"
if [[ "$OS" == "Darwin" ]]; then
    warn "macOS detected. apt installs will be skipped. Go/pip/npm will still run."
fi

# ── APT prefix ────────────────────────────────────────────────────────────────
APT_CMD="apt-get"
if [[ $EUID -ne 0 ]] && command -v sudo &>/dev/null; then
    APT_CMD="sudo apt-get"
fi

# ==============================================================================
# 1. APT — system packages
# FIX: Removed packages that are NOT in standard apt repos on Kali/Debian
#      (subfinder, amass, nuclei, assetfinder, dnsx, gau, etc. are Go tools)
#      httpx on Kali is httpx-toolkit but installs binary as 'httpx'
# ==============================================================================
APT_CORE=(
    dnsutils          # dig, nslookup
    bind9-host        # host
    whois curl git jq
    coreutils         # timeout
    netcat-openbsd    # nc
    nmap
    nikto
    sqlmap
    sslyze
    python3 python3-pip python3-venv
    ruby ruby-dev     # for wpscan gem
    cargo             # for rustscan / feroxbuster fallback
    npm               # for newman / retire.js
)

# FIX: Packages that exist in Kali repos but NOT standard Debian/Ubuntu
KALI_OPTIONAL=(
    httpx-toolkit     # installs as 'httpx'
    subfinder
    amass
    nuclei
    ffuf
    feroxbuster
    dirsearch
    wpscan
    wapiti
    skipfish
    gau
    waybackurls
    gospider
    hakrawler
    katana
    dalfox
    subjack
    gitleaks
    trufflehog        # in Kali repos as binary; pip version is DEPRECATED
    arjun
    assetfinder
    dnsx
    asnmap
    mapcidr
    rustscan
    testssl.sh
    cmsmap
)

if command -v apt-get &>/dev/null; then
    info "Updating apt cache..."
    $APT_CMD update -qq 2>/dev/null || warn "apt update had errors (continuing)"

    info "Installing core system packages..."
    DEBIAN_FRONTEND=noninteractive $APT_CMD install -y "${APT_CORE[@]}" 2>/dev/null \
        || warn "Some core packages failed — proceeding anyway"

    info "Trying Kali-optional packages (non-fatal)..."
    for pkg in "${KALI_OPTIONAL[@]}"; do
        DEBIAN_FRONTEND=noninteractive $APT_CMD install -y "$pkg" -qq 2>/dev/null \
            && ok "$pkg (apt)" \
            || warn "$pkg not in apt — will use Go/pip fallback"
    done
else
    warn "apt-get not found. Install packages manually."
fi

# ==============================================================================
# 2. Go — install Go itself if missing, then install Go tools
# FIX: Export GOPATH/GOBIN properly so installed binaries are on PATH immediately
# ==============================================================================

# FIX: Set Go env vars BEFORE any go install calls
export GOPATH="${GOPATH:-$HOME/go}"
export GOBIN="${GOBIN:-$HOME/go/bin}"
export PATH="$GOBIN:/usr/local/go/bin:$PATH"

# Auto-install Go if missing
if ! command -v go &>/dev/null; then
    warn "Go not found — attempting auto-install..."
    GO_VERSION="1.22.4"
    GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
    GO_URL="https://go.dev/dl/${GO_TAR}"
    if curl -fsSL "$GO_URL" -o "/tmp/${GO_TAR}" 2>/dev/null; then
        $([[ $EUID -ne 0 ]] && echo "sudo" || echo "") tar -C /usr/local -xzf "/tmp/${GO_TAR}" 2>/dev/null \
            && ok "Go ${GO_VERSION} installed" \
            || err "Go tar extract failed — install manually from https://go.dev/dl/"
    else
        err "Could not download Go — install manually. Go tools will be skipped."
    fi
fi

# FIX: Wrapper that checks AFTER install whether binary is available
install_go_tool() {
    local cmd="$1"
    local pkg="$2"
    if command -v "$cmd" &>/dev/null; then
        ok "$cmd (already installed)"
        return 0
    fi
    if ! command -v go &>/dev/null; then
        warn "go not available — skipping $cmd"
        return 1
    fi
    info "Installing $cmd via Go..."
    if go install -v "$pkg" 2>/dev/null; then
        # FIX: Re-check with full path in case PATH not yet updated
        if command -v "$cmd" &>/dev/null || [[ -f "$GOBIN/$cmd" ]]; then
            ok "$cmd installed"
        else
            warn "$cmd binary not found after install (check GOBIN=$GOBIN)"
        fi
    else
        err "$cmd go install failed"
    fi
}

if command -v go &>/dev/null; then
    info "Installing Go-based tools..."

    # Phase 1 — Discovery
    install_go_tool subfinder    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    install_go_tool amass        "github.com/owasp-amass/amass/v4/...@master"
    install_go_tool assetfinder  "github.com/tomnomnom/assetfinder@latest"
    install_go_tool dnsx         "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    install_go_tool httpx        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    install_go_tool asnmap       "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    install_go_tool mapcidr      "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"

    # Phase 2 — Intel / takeover
    install_go_tool nuclei       "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    install_go_tool subjack      "github.com/haccer/subjack@latest"
    install_go_tool subover      "github.com/Ice3man543/SubOver@latest"
    install_go_tool gitleaks     "github.com/gitleaks/gitleaks/v8@latest"
    # FIX: trufflehog pip is DEPRECATED — use official Go/curl installer
    if ! command -v trufflehog &>/dev/null; then
        info "Installing trufflehog via official installer..."
        curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
            | sh -s -- -b "$GOBIN" 2>/dev/null \
            && ok "trufflehog installed" \
            || install_go_tool trufflehog "github.com/trufflesecurity/trufflehog/v3@latest"
    else
        ok "trufflehog (already installed)"
    fi

    # Phase 3 — Content discovery / crawling
    install_go_tool gau          "github.com/lc/gau/v2/cmd/gau@latest"
    install_go_tool waybackurls  "github.com/tomnomnom/waybackurls@latest"
    install_go_tool gospider     "github.com/jaeles-project/gospider@latest"
    install_go_tool hakrawler    "github.com/hakluke/hakrawler@latest"
    install_go_tool katana       "github.com/projectdiscovery/katana/cmd/katana@latest"
    install_go_tool ffuf         "github.com/ffuf/ffuf/v2@latest"
    install_go_tool cariddi      "github.com/edoardottt/cariddi/cmd/cariddi@latest"
    install_go_tool mantra       "github.com/Brosck/mantra@latest"

    # Phase 4 — Vuln scanning
    install_go_tool dalfox       "github.com/hahwul/dalfox/v2@latest"
    install_go_tool gowitness    "github.com/sensepost/gowitness@latest"

    # Extra
    install_go_tool dnsprober    "github.com/mrhenrike/dnsprober@latest"
    install_go_tool subprober    "github.com/0xSojalSec/Subprober@latest"
else
    warn "Go not available — Go tools skipped. Install Go from https://go.dev/dl/"
fi

# ==============================================================================
# 3. npm tools — newman, retire.js
# ==============================================================================
if command -v npm &>/dev/null; then
    info "Installing newman and retire.js..."
    npm install -g newman 2>/dev/null && ok "newman" || warn "newman npm install failed"
    npm install -g retire  2>/dev/null && ok "retire"  || warn "retire.js npm install failed"
else
    warn "npm not found — newman and retire.js skipped"
fi

# ==============================================================================
# 4. Git-cloned tools
# ==============================================================================

# FIX: Check if binary already exists before cloning; use -f for symlink
clone_tool() {
    local name="$1" url="$2" dest="$3"
    if [[ -d "$dest" ]]; then
        ok "$name (already cloned at $dest)"
    else
        info "Cloning $name..."
        git clone --depth 1 "$url" "$dest" 2>/dev/null && ok "$name cloned" || err "$name clone failed"
    fi
}

clone_tool "LinkFinder"  "https://github.com/GerbenJavado/LinkFinder.git"  "/opt/LinkFinder"
clone_tool "SecretFinder" "https://github.com/m4ll0k/SecretFinder.git"     "/opt/SecretFinder"

# git-secrets
if command -v git-secrets &>/dev/null; then
    ok "git-secrets (already installed)"
else
    info "Installing git-secrets..."
    # FIX: Remove stale clone dir before re-cloning
    rm -rf /tmp/git-secrets 2>/dev/null
    if git clone https://github.com/awslabs/git-secrets.git /tmp/git-secrets 2>/dev/null; then
        (cd /tmp/git-secrets && make install 2>/dev/null) && ok "git-secrets" || err "git-secrets make install failed"
    else
        err "git-secrets clone failed"
    fi
fi

# testssl.sh fallback (if not installed via apt)
if ! command -v testssl.sh &>/dev/null && ! command -v testssl &>/dev/null; then
    clone_tool "testssl.sh" "https://github.com/drwetter/testssl.sh.git" "/opt/testssl.sh"
    if [[ -f /opt/testssl.sh/testssl.sh ]]; then
        # FIX: Use -f to force overwrite existing symlink
        ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh 2>/dev/null && ok "testssl.sh symlinked"
    fi
fi

# GoWitness git fallback (if go install failed)
if ! command -v gowitness &>/dev/null; then
    clone_tool "gowitness" "https://github.com/sensepost/gowitness.git" "/opt/gowitness"
    if [[ -d /opt/gowitness ]] && command -v go &>/dev/null; then
        (cd /opt/gowitness && go build -o /usr/local/bin/gowitness . 2>/dev/null) \
            && ok "gowitness built from source" \
            || err "gowitness build failed"
    fi
fi

# ==============================================================================
# 5. Cargo tools (rustscan, feroxbuster) — fallback if not in apt
# ==============================================================================
if command -v cargo &>/dev/null; then
    for cargo_tool in rustscan feroxbuster; do
        if ! command -v "$cargo_tool" &>/dev/null; then
            info "Installing $cargo_tool via cargo..."
            cargo install "$cargo_tool" 2>/dev/null && ok "$cargo_tool" || warn "$cargo_tool cargo install failed"
        else
            ok "$cargo_tool (already installed)"
        fi
    done
else
    warn "cargo not found — rustscan/feroxbuster cargo fallback skipped"
fi

# ==============================================================================
# 6. wpscan (Ruby gem)
# ==============================================================================
if command -v wpscan &>/dev/null; then
    ok "wpscan (already installed)"
elif command -v gem &>/dev/null; then
    info "Installing wpscan gem..."
    gem install wpscan 2>/dev/null && ok "wpscan" || warn "wpscan gem install failed"
else
    warn "gem not found — wpscan skipped"
fi

# ==============================================================================
# 7. Python virtualenv + pip packages
# FIX: run_pip() had broken fallback — pip3 --break-system-packages before subcommand
# FIX: trufflehog removed from pip list (DEPRECATED)
# ==============================================================================
PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" &>/dev/null; then
    err "$PYTHON not found — Python deps cannot be installed"
else
    VENV_DIR="${VENV_DIR:-.venv}"

    # Create venv if missing
    if [[ ! -d "$VENV_DIR" ]]; then
        info "Creating virtualenv at $VENV_DIR..."
        "$PYTHON" -m venv "$VENV_DIR" 2>/dev/null \
            || "$PYTHON" -m venv --without-pip "$VENV_DIR" 2>/dev/null \
            || warn "venv creation failed"
    fi

    # Locate venv pip
    _VENV_PIP=""
    for _p in \
        "$VENV_DIR/bin/pip" \
        "$VENV_DIR/bin/pip3" \
        "$SCRIPT_DIR/$VENV_DIR/bin/pip"; do
        [[ -x "$_p" ]] && { _VENV_PIP="$_p"; break; }
    done

    # Bootstrap pip if venv was created --without-pip
    if [[ -z "$_VENV_PIP" ]]; then
        _VP=""
        for _v in "$VENV_DIR/bin/python" "$VENV_DIR/bin/python3" "$SCRIPT_DIR/$VENV_DIR/bin/python"; do
            [[ -x "$_v" ]] && { _VP="$_v"; break; }
        done
        if [[ -n "$_VP" ]]; then
            info "Bootstrapping pip via ensurepip..."
            "$_VP" -m ensurepip --upgrade 2>/dev/null \
                || curl -fsSL https://bootstrap.pypa.io/get-pip.py | "$_VP" 2>/dev/null \
                || warn "pip bootstrap failed"
            [[ -x "$VENV_DIR/bin/pip" ]]  && _VENV_PIP="$VENV_DIR/bin/pip"
            [[ -x "$VENV_DIR/bin/pip3" ]] && _VENV_PIP="$VENV_DIR/bin/pip3"
        fi
    fi

    # FIX: run_pip — flags AFTER subcommand, not before
    run_pip() {
        if [[ -n "$_VENV_PIP" ]]; then
            "$_VENV_PIP" "$@"
        else
            warn "venv pip unavailable; using system pip3 --break-system-packages"
            # FIX: --break-system-packages goes AFTER install/upgrade, not before
            pip3 "$@" --break-system-packages 2>/dev/null || true
        fi
    }

    info "Upgrading pip inside venv..."
    run_pip install --upgrade pip -q 2>/dev/null || warn "pip upgrade failed"

    # FIX: Removed trufflehog from pip list (no longer maintained on PyPI)
    PIP_TOOLS=(
        arjun
        dirsearch
        sslyze
        censys
        shodan
        requests
        beautifulsoup4
        lxml
    )

    info "Installing pip tools into venv..."
    for pt in "${PIP_TOOLS[@]}"; do
        run_pip install -q "$pt" 2>/dev/null && ok "$pt (pip)" || warn "$pt pip install failed"
    done

    # requirements.txt files
    for req in "$SCRIPT_DIR/requirements.txt" "$SCRIPT_DIR/requirements-api.txt"; do
        if [[ -f "$req" ]]; then
            info "Installing from $(basename "$req")..."
            run_pip install -r "$req" -q 2>/dev/null \
                && ok "$(basename "$req") installed" \
                || warn "Some packages in $(basename "$req") failed"
        fi
    done
fi

# ==============================================================================
# 8. Nuclei — update templates after install
# ==============================================================================
if command -v nuclei &>/dev/null || [[ -f "$GOBIN/nuclei" ]]; then
    info "Updating nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null && ok "nuclei templates updated" || warn "nuclei template update failed"
fi

# ==============================================================================
# 9. Make scripts executable
# FIX: Guard against missing modules/ directory
# ==============================================================================
RUN_SCAN="$SCRIPT_DIR/lib/run_scan.sh"
[[ -f "$RUN_SCAN" ]] && chmod +x "$RUN_SCAN" && ok "lib/run_scan.sh is executable"

if [[ -d "$SCRIPT_DIR/modules" ]]; then
    # FIX: Glob safely — only run chmod if .sh files exist
    shopt -s nullglob
    mod_files=("$SCRIPT_DIR"/modules/*.sh)
    shopt -u nullglob
    if [[ ${#mod_files[@]} -gt 0 ]]; then
        chmod +x "${mod_files[@]}" && ok "${#mod_files[@]} module script(s) made executable"
    else
        warn "No .sh files found in modules/"
    fi
else
    warn "modules/ directory not found — skipping chmod"
fi

# ==============================================================================
# 10. Version report
# FIX: Safe version check — catch tools that crash or have no --version flag
# ==============================================================================
echo ""
echo "══════════════════════════════════════════════════════════════"
echo " Technieum — Installed Tool Report"
echo "══════════════════════════════════════════════════════════════"

ALL_TOOLS=(
    # Core
    dig nslookup host whois curl jq git timeout python3 go
    # Phase 1
    subfinder amass assetfinder dnsx httpx asnmap mapcidr
    # Phase 2
    nmap nc rustscan nuclei subjack subover gitleaks trufflehog git-secrets
    # Phase 3
    gau waybackurls gospider hakrawler katana ffuf feroxbuster dirsearch
    newman arjun cariddi mantra
    # Phase 4
    dalfox sqlmap nikto wpscan wapiti skipfish cmsmap
    testssl.sh testssl sslyze retire gowitness
)

get_version() {
    local cmd="$1"
    local ver=""
    # FIX: Try each flag; suppress stderr; timeout to avoid hangs
    for flag in "--version" "-version" "-V" "-v" "version"; do
        ver=$(timeout 5 "$cmd" $flag 2>/dev/null | head -1 || true)
        [[ -n "$ver" ]] && { echo "$ver"; return; }
    done
    echo "(installed — version unknown)"
}

for cmd in "${ALL_TOOLS[@]}"; do
    if command -v "$cmd" &>/dev/null; then
        ver=$(get_version "$cmd")
        printf "  ${GRN}%-22s${NC} %s\n" "$cmd" "$ver"
    else
        printf "  ${RED}%-22s${NC} NOT FOUND\n" "$cmd"
    fi
done

echo ""
echo "  Python : $("$PYTHON" --version 2>&1)"
if [[ -n "${_VENV_PIP:-}" ]]; then
    echo "  pip    : $("$_VENV_PIP" --version 2>&1 | head -1)"
else
    echo "  pip    : (venv pip unavailable)"
fi
echo "  GOBIN  : ${GOBIN}"
echo "  venv   : ${VENV_DIR}"
echo ""
echo "══════════════════════════════════════════════════════════════"
echo " Done. Run: ./start.sh"
echo "        Or: ./lib/run_scan.sh 1 example.com full"
echo "══════════════════════════════════════════════════════════════"
