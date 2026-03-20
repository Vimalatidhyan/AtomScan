#!/usr/bin/env bash
# ==============================================================================
# Technieum — Full Tool Installer
# Installs all system packages, Go tools, Python tools, and wordlists.
# Supports: Kali Linux, Debian 12+, Ubuntu 22.04+, Arch/Manjaro
#
# Usage:  sudo bash install.sh
#         sudo bash install.sh --skip-wordlists   (skip SecLists ~2 GB)
#         sudo bash install.sh --python-only       (Python deps only)
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Colours
# ------------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()    { echo -e "${GREEN}[+]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
log_error()   { echo -e "${RED}[-]${NC} $*" >&2; }
log_section() { echo -e "\n${CYAN}${BOLD}[*] $*${NC}\n"; }
log_ok()      { echo -e "${GREEN}[✓]${NC} $*"; }

# ------------------------------------------------------------------------------
# Argument parsing
# ------------------------------------------------------------------------------
SKIP_WORDLISTS=false
PYTHON_ONLY=false
for arg in "$@"; do
    case "$arg" in
        --skip-wordlists) SKIP_WORDLISTS=true ;;
        --python-only)    PYTHON_ONLY=true ;;
        --help|-h)
            echo "Usage: sudo bash install.sh [--skip-wordlists] [--python-only]"
            exit 0
            ;;
    esac
done

# ------------------------------------------------------------------------------
# Root check
# ------------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    log_error "Run as root:  sudo bash install.sh"
    exit 1
fi

# Preserve the real user's home for Go/PATH settings
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

# ------------------------------------------------------------------------------
# OS detection
# ------------------------------------------------------------------------------
if [[ -f /etc/os-release ]]; then
    # shellcheck source=/dev/null
    source /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_LIKE="${ID_LIKE:-}"
else
    log_error "Cannot detect OS — /etc/os-release not found."
    exit 1
fi

log_info "OS: $PRETTY_NAME"
log_info "Real user home: $REAL_HOME"

# ------------------------------------------------------------------------------
# Directories
# ------------------------------------------------------------------------------
TOOLS_DIR="/opt/technieum-tools"
WORDLISTS_DIR="/opt/wordlists"
mkdir -p "$TOOLS_DIR" "$WORDLISTS_DIR"

# ==============================================================================
# HELPER: safe Go install (non-fatal)
# ==============================================================================
go_install() {
    local pkg="$1"
    local bin
    bin="$(basename "${pkg%%@*}")"
    log_info "go install $pkg"
    if ! go install "$pkg" 2>/dev/null; then
        log_warn "Failed to install Go package: $pkg"
    fi
}

# ==============================================================================
# HELPER: git clone or pull
# ==============================================================================
git_sync() {
    local url="$1" dest="$2"
    if [[ -d "$dest/.git" ]]; then
        log_info "Updating $(basename "$dest")..."
        git -C "$dest" pull --ff-only --quiet || log_warn "Update failed for $dest"
    else
        log_info "Cloning $(basename "$dest")..."
        git clone --depth 1 --quiet "$url" "$dest" || log_warn "Clone failed: $url"
    fi
}

# ==============================================================================
# HELPER: pip install (non-fatal)
# ==============================================================================
pip_install() {
    "$PIP" install --quiet --break-system-packages "$@" 2>/dev/null \
        || "$PIP" install --quiet "$@" 2>/dev/null \
        || log_warn "pip install failed for: $*"
}

if $PYTHON_ONLY; then
    log_section "Python-only mode: skipping system/Go tools"
fi

# ==============================================================================
# 1. SYSTEM PACKAGES
# ==============================================================================
if ! $PYTHON_ONLY; then
    log_section "System Packages"

    case "$OS_ID" in
        kali|debian|ubuntu|parrot|linuxmint)
            # Resolve chromium package name (differs across distros)
            CHROMIUM_PKG=""
            for pkg in chromium-browser chromium; do
                if apt-cache show "$pkg" &>/dev/null; then
                    CHROMIUM_PKG="$pkg"; break
                fi
            done

            DEBIAN_FRONTEND=noninteractive apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
                python3 python3-pip python3-venv python3-dev \
                git curl wget jq unzip \
                build-essential libssl-dev libffi-dev \
                whois dnsutils \
                nmap masscan \
                nikto sqlmap \
                ruby ruby-dev \
                nodejs npm \
                default-jre \
                ${CHROMIUM_PKG:+"$CHROMIUM_PKG"} \
                2>/dev/null || log_warn "Some apt packages failed — continuing"
            ;;

        arch|manjaro|endeavouros)
            pacman -Syu --noconfirm --needed \
                python python-pip \
                git curl wget jq unzip \
                base-devel openssl \
                whois bind \
                nmap masscan \
                nikto sqlmap \
                ruby nodejs npm \
                jre-openjdk chromium \
                2>/dev/null || log_warn "Some pacman packages failed — continuing"
            ;;

        fedora|rhel|centos|rocky|almalinux)
            dnf install -y \
                python3 python3-pip python3-devel \
                git curl wget jq unzip \
                gcc openssl-devel libffi-devel \
                whois bind-utils \
                nmap masscan \
                ruby nodejs \
                chromium \
                2>/dev/null || log_warn "Some dnf packages failed — continuing"
            ;;

        *)
            log_warn "Unsupported OS '$OS_ID' — skipping system packages. Install manually."
            ;;
    esac
    log_ok "System packages done"
fi

# ==============================================================================
# 2. GO INSTALLATION
# ==============================================================================
if ! $PYTHON_ONLY; then
    log_section "Go Language Runtime"

    GO_VERSION="1.22.4"
    ARCH="$(uname -m)"
    case "$ARCH" in
        x86_64)  GO_ARCH="amd64" ;;
        aarch64) GO_ARCH="arm64" ;;
        armv7l)  GO_ARCH="armv6l" ;;
        *)       GO_ARCH="amd64" ;;
    esac

    CURRENT_GO=""
    if command -v /usr/local/go/bin/go &>/dev/null; then
        CURRENT_GO="$(/usr/local/go/bin/go version 2>/dev/null | awk '{print $3}' | sed 's/go//')"
    fi

    if [[ "$CURRENT_GO" < "$GO_VERSION" ]] || [[ -z "$CURRENT_GO" ]]; then
        log_info "Installing Go $GO_VERSION (${GO_ARCH})..."
        GO_TAR="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
        wget -q "https://go.dev/dl/${GO_TAR}" -O "/tmp/${GO_TAR}"
        rm -rf /usr/local/go
        tar -C /usr/local -xzf "/tmp/${GO_TAR}"
        rm -f "/tmp/${GO_TAR}"
        log_ok "Go $GO_VERSION installed"
    else
        log_ok "Go $CURRENT_GO already installed"
    fi

    export GOROOT=/usr/local/go
    export GOPATH="${REAL_HOME}/go"
    export PATH="${GOROOT}/bin:${GOPATH}/bin:${PATH}"

    # Write Go env to real user's profile
    PROFILE_FILE="${REAL_HOME}/.bashrc"
    if ! grep -q 'GOROOT=/usr/local/go' "$PROFILE_FILE" 2>/dev/null; then
        cat >> "$PROFILE_FILE" <<'GOENV'

# --- Go environment (added by Technieum installer) ---
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$GOROOT/bin:$GOPATH/bin:$PATH
GOENV
        log_ok "Go paths added to $PROFILE_FILE"
    fi
fi

# ==============================================================================
# 3. GO TOOLS
# ==============================================================================
if ! $PYTHON_ONLY; then
    log_section "Go Security Tools"

    declare -A GO_TOOLS=(
        # Subdomain enumeration
        ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ["amass"]="github.com/owasp-amass/amass/v4/...@master"
        ["assetfinder"]="github.com/tomnomnom/assetfinder@latest"
        ["shuffledns"]="github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"

        # HTTP probing
        ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
        ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"

        # DNS
        ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        ["puredns"]="github.com/d3mondev/puredns/v2@latest"

        # Port scanning
        ["naabu"]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"

        # Vulnerability scanning
        ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

        # Content discovery
        ["ffuf"]="github.com/ffuf/ffuf/v2@latest"
        ["feroxbuster"]="github.com/epi052/feroxbuster@latest"

        # URL collection
        ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
        ["waybackurls"]="github.com/tomnomnom/waybackurls@latest"
        ["hakrawler"]="github.com/hakluke/hakrawler@latest"

        # Takeover / misconfiguration
        ["subjack"]="github.com/haccer/subjack@latest"
        ["subzy"]="github.com/LukaSikic/subzy@latest"

        # Leak detection
        ["gitleaks"]="github.com/gitleaks/gitleaks/v8@latest"

        # Miscellaneous
        ["anew"]="github.com/tomnomnom/anew@latest"
        ["qsreplace"]="github.com/tomnomnom/qsreplace@latest"
    )

    for bin in "${!GO_TOOLS[@]}"; do
        if ! command -v "$bin" &>/dev/null; then
            go_install "${GO_TOOLS[$bin]}"
        else
            log_ok "$bin already installed"
        fi
    done

    # Update Nuclei templates
    if command -v nuclei &>/dev/null; then
        log_info "Updating Nuclei templates..."
        nuclei -update-templates -silent 2>/dev/null || log_warn "Nuclei template update failed"
    fi
fi

# ==============================================================================
# 4. RUST TOOLS
# ==============================================================================
if ! $PYTHON_ONLY; then
    log_section "Rust-based Tools"

    # Install RustScan via cargo if available
    if command -v cargo &>/dev/null; then
        if ! command -v rustscan &>/dev/null; then
            log_info "Installing RustScan..."
            cargo install rustscan --quiet 2>/dev/null || log_warn "RustScan install failed"
        else
            log_ok "RustScan already installed"
        fi
    else
        log_warn "Rust/cargo not found — install Rust from https://rustup.rs to get RustScan"
    fi
fi

# ==============================================================================
# 5. PYTHON ENVIRONMENT
# ==============================================================================
log_section "Python Dependencies"

# Kali uses PEP 668 managed environment — create a project venv instead
VENV_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")/.venv"
if python3 -m venv --help &>/dev/null; then
    if [[ ! -d "$VENV_DIR" ]]; then
        log_info "Creating Python venv at $VENV_DIR..."
        python3 -m venv "$VENV_DIR"
    fi
    PIP="$VENV_DIR/bin/pip"
    PYTHON="$VENV_DIR/bin/python"
else
    PIP="pip3"
    PYTHON="python3"
fi

log_info "Upgrading pip..."
"$PIP" install --quiet --upgrade pip

log_info "Installing Python requirements..."
SCRIPT_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
if [[ -f "$SCRIPT_DIR/requirements.txt" ]]; then
    "$PIP" install --quiet -r "$SCRIPT_DIR/requirements.txt"
    log_ok "Python requirements installed"
else
    log_warn "requirements.txt not found — skipping Python deps"
fi

# ==============================================================================
# 6. PYTHON-BASED TOOLS (system-wide)
# ==============================================================================
if ! $PYTHON_ONLY; then
    log_section "Python-based Security Tools"

    # These are installed system-wide (or per-venv for Kali)
    PYTOOLS=(
        "sublist3r"
        "truffleHog"
        "arjun"
        "wafw00f"
        "sqlmap"
    )

    for tool in "${PYTOOLS[@]}"; do
        log_info "pip install $tool..."
        pip_install "$tool"
    done

    # WPScan (Ruby gem)
    if command -v gem &>/dev/null && ! command -v wpscan &>/dev/null; then
        log_info "Installing WPScan..."
        gem install wpscan --quiet 2>/dev/null || log_warn "WPScan install failed"
    fi

    # testssl.sh
    if [[ ! -f "$TOOLS_DIR/testssl.sh/testssl.sh" ]]; then
        git_sync "https://github.com/drwetter/testssl.sh.git" "$TOOLS_DIR/testssl.sh"
        ln -sf "$TOOLS_DIR/testssl.sh/testssl.sh" /usr/local/bin/testssl.sh 2>/dev/null || true
    else
        log_ok "testssl.sh already installed"
    fi

    # LinkFinder
    if [[ ! -d "$TOOLS_DIR/LinkFinder" ]]; then
        git_sync "https://github.com/GerbenJavado/LinkFinder.git" "$TOOLS_DIR/LinkFinder"
        pip_install -r "$TOOLS_DIR/LinkFinder/requirements.txt"
    else
        log_ok "LinkFinder already installed"
    fi
fi

# ==============================================================================
# 7. WORDLISTS
# ==============================================================================
if ! $PYTHON_ONLY && ! $SKIP_WORDLISTS; then
    log_section "Wordlists"

    if [[ ! -d "$WORDLISTS_DIR/SecLists" ]]; then
        log_info "Downloading SecLists (~2 GB)..."
        git_sync "https://github.com/danielmiessler/SecLists.git" "$WORDLISTS_DIR/SecLists"
        log_ok "SecLists installed at $WORDLISTS_DIR/SecLists"
    else
        log_ok "SecLists already installed"
    fi
else
    [[ "$SKIP_WORDLISTS" == "true" ]] && log_warn "Skipping wordlists (--skip-wordlists)"
fi

# ==============================================================================
# 8. CONFIGURATION
# ==============================================================================
log_section "Configuration"

SCRIPT_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"

# Create .env from example if not present
if [[ ! -f "$SCRIPT_DIR/.env" ]]; then
    if [[ -f "$SCRIPT_DIR/.env.example" ]]; then
        cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
        chown "$REAL_USER":"$REAL_USER" "$SCRIPT_DIR/.env"
        log_ok ".env created from .env.example — add your API keys"
    else
        cat > "$SCRIPT_DIR/.env" <<'ENVFILE'
# Technieum API Keys — see README.md for how to obtain each key
SHODAN_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=
SECURITYTRAILS_API_KEY=
VIRUSTOTAL_API_KEY=
GREYNOISE_API_KEY=
ABUSEIPDB_API_KEY=
OTX_API_KEY=
CROWDSEC_API_KEY=
DEHASHED_EMAIL=
DEHASHED_KEY=
GITHUB_TOKEN=
NVD_API_KEY=
EMAILREP_API_KEY=
DATABASE_URL=sqlite:///./technieum.db
SECRET_KEY=change-me-to-a-random-64-char-string
LOG_LEVEL=INFO
ENVFILE
        chown "$REAL_USER":"$REAL_USER" "$SCRIPT_DIR/.env"
        log_ok ".env created — fill in your API keys (see README.md)"
    fi
else
    log_ok ".env already exists"
fi

# Create directories
mkdir -p "$SCRIPT_DIR/output" "$SCRIPT_DIR/logs"
chown -R "$REAL_USER":"$REAL_USER" "$SCRIPT_DIR/output" "$SCRIPT_DIR/logs"

# Make scripts executable
chmod +x "$SCRIPT_DIR/technieum.py" \
         "$SCRIPT_DIR/setup.sh" \
         "$SCRIPT_DIR/install.sh" \
         "$SCRIPT_DIR"/modules/*.sh 2>/dev/null || true

# ==============================================================================
# 9. VERIFICATION
# ==============================================================================
log_section "Verification"

PASS=0; FAIL=0

check_tool() {
    local name="$1"
    if command -v "$name" &>/dev/null; then
        log_ok "$name"
        ((PASS++))
    else
        log_warn "$name not found"
        ((FAIL++))
    fi
}

CORE_TOOLS=(python3 pip3 nmap sqlite3 curl wget git jq)
GO_BINS=(subfinder httpx nuclei ffuf dnsx gau waybackurls anew subjack gitleaks)
OPTIONAL=(amass katana naabu feroxbuster rustscan wpscan)

echo "── Core ──────────────────────"
for t in "${CORE_TOOLS[@]}"; do check_tool "$t"; done
echo "── Go tools ──────────────────"
for t in "${GO_BINS[@]}"; do check_tool "$t"; done
echo "── Optional ──────────────────"
for t in "${OPTIONAL[@]}"; do check_tool "$t"; done

echo ""
log_info "Results: ${GREEN}${PASS} ok${NC}  ${YELLOW}${FAIL} missing${NC}"
echo ""

# ==============================================================================
# 10. SUMMARY
# ==============================================================================
log_section "Installation Complete"

cat <<SUMMARY
${BOLD}Next steps:${NC}
  1. ${YELLOW}Add API keys${NC} to .env:
        nano $SCRIPT_DIR/.env

  2. ${YELLOW}Activate the Python venv${NC} (Kali/Debian) before running:
        source $VENV_DIR/bin/activate

  3. ${YELLOW}Run Technieum${NC}:
        python3 $SCRIPT_DIR/technieum.py -t example.com

  4. ${YELLOW}Optional — start the web API${NC}:
        uvicorn backend.api.server:app --host 0.0.0.0 --port 8000

  5. ${YELLOW}Reload Go paths${NC} in current shell:
        source $REAL_HOME/.bashrc

See README.md for full documentation.
SUMMARY

exit 0
