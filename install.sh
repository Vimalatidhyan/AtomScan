#!/bin/bash
################################################################################
# ReconX Installation Script
# Installs all required tools for comprehensive attack surface management
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_section() {
    echo -e "\n${BLUE}[*] $1${NC}\n"
}

git_clone_or_pull() {
    local repo_url="$1"
    local dest_dir="$2"
    local repo_name

    if [ -z "$repo_url" ] || [ -z "$dest_dir" ]; then
        return 1
    fi

    repo_name="$(basename "$dest_dir")"

    if [ -d "$dest_dir/.git" ]; then
        log_info "Updating $repo_name..."
        (cd "$dest_dir" && GIT_TERMINAL_PROMPT=0 git pull --ff-only) || log_warn "Failed to update $repo_name"
    else
        log_info "Cloning $repo_name..."
        GIT_TERMINAL_PROMPT=0 git clone --depth 1 "$repo_url" "$dest_dir" || log_warn "Failed to clone $repo_name"
    fi
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root (use sudo)"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    log_error "Cannot detect OS"
    exit 1
fi

log_info "Detected OS: $OS"

# Create installation directory
INSTALL_DIR="/opt"
TOOLS_DIR="$INSTALL_DIR/reconx-tools"
mkdir -p "$TOOLS_DIR"

################################################################################
# System Package Installation
################################################################################

log_section "Installing System Packages"

if [ "$OS" = "kali" ] || [ "$OS" = "debian" ] || [ "$OS" = "ubuntu" ]; then
    # Chromium package name varies by distro (kali/debian/ubuntu)
    CHROMIUM_PKG=""
    if apt-cache policy chromium-browser 2>/dev/null | awk '/Candidate:/ {print $2}' | grep -vq "(none)"; then
        CHROMIUM_PKG="chromium-browser"
    elif apt-cache policy chromium 2>/dev/null | awk '/Candidate:/ {print $2}' | grep -vq "(none)"; then
        CHROMIUM_PKG="chromium"
    else
        log_warn "Chromium package not found; skipping browser install"
    fi

    apt-get update
    apt-get install -y \
        python3 python3-pip python3-venv \
        git curl wget jq \
        build-essential \
        libssl-dev libffi-dev \
        whois dnsutils \
        nmap masscan \
        nikto sqlmap \
        skipfish \
        p0f \
        $CHROMIUM_PKG \
        default-jre \
        nodejs npm \
        ruby ruby-dev \
        golang-go \
        docker.io \
        unzip

elif [ "$OS" = "arch" ] || [ "$OS" = "manjaro" ]; then
    pacman -Syu --noconfirm
    pacman -S --noconfirm \
        python python-pip \
        git curl wget jq \
        base-devel \
        openssl \
        whois bind-tools \
        nmap masscan \
        nikto sqlmap \
        p0f \
        chromium \
        jre-openjdk \
        nodejs npm \
        ruby \
        go \
        docker \
        unzip

else
    log_warn "Unsupported OS. Please install dependencies manually."
fi

################################################################################
# Python Environment Setup
################################################################################

log_section "Setting Up Python Environment"

VENV_DIR="$TOOLS_DIR/venv"
PIP_CMD="pip3"
PYTHON_CMD="python3"

create_py_wrapper() {
    local name="$1"
    local script_path="$2"

    if [ -z "$name" ] || [ -z "$script_path" ]; then
        return 1
    fi

    cat > "/usr/local/bin/$name" <<EOF
#!/bin/bash
exec "$PYTHON_CMD" "$script_path" "\$@"
EOF
    chmod +x "/usr/local/bin/$name" || true
}

# Kali uses PEP 668; prefer a dedicated venv for all Python tools
if [ "$OS" = "kali" ]; then
    log_info "Creating Python venv for tool installs (Kali PEP 668 compliant)..."
    python3 -m venv "$VENV_DIR" || log_warn "Failed to create venv"
    PIP_CMD="$VENV_DIR/bin/pip"
    PYTHON_CMD="$VENV_DIR/bin/python"
    export PATH="$VENV_DIR/bin:$PATH"
fi

################################################################################
# Python Dependencies
################################################################################

log_section "Installing Python Dependencies"

"$PIP_CMD" install --upgrade pip
"$PIP_CMD" install \
    requests \
    beautifulsoup4 \
    dnspython \
    pyyaml \
    colorama \
    tqdm \
    aiohttp \
    lxml

################################################################################
# Go Tools Installation
################################################################################

log_section "Installing Go Tools"

# Set Go environment
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin

# Update Go (if needed)
GO_VERSION="1.21.0"
if ! command -v go &> /dev/null || [ "$(go version | awk '{print $3}' | sed 's/go//')" \< "$GO_VERSION" ]; then
    log_info "Installing/Updating Go..."
    wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
    rm go${GO_VERSION}.linux-amd64.tar.gz
fi

log_info "Installing Go-based reconnaissance tools..."

# Subdomain Enumeration
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@master

# Certificate Transparency / ASN / Cloud
go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go install -v github.com/tomnomnom/goblob@latest

# DNS Tools
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/ProjectAnte/dnsgen@latest || log_warn "dnsgen install failed"

# HTTP Probing
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Port Scanning
go install -v github.com/RustScan/RustScan@latest || log_warn "RustScan install failed, install manually with cargo"

# URL Discovery
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/hakluke/hakrawler@latest

# Web Crawling
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Directory Bruteforce
go install -v github.com/ffuf/ffuf/v2@latest

# Vulnerability Scanning
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Takeover Detection
go install -v github.com/haccer/subjack@latest

# Parameter Discovery
go install -v github.com/s0md3v/Arjun@latest || log_warn "Arjun Go install failed"

# XSS
go install -v github.com/hahwul/dalfox/v2@latest

# API Discovery
log_info "Installing Kiterunner..."
git_clone_or_pull "https://github.com/assetnote/kiterunner.git" "$TOOLS_DIR/kiterunner"
if [ -d "$TOOLS_DIR/kiterunner" ]; then
    cd "$TOOLS_DIR/kiterunner" && make build && ln -sf "$TOOLS_DIR/kiterunner/dist/kr" /usr/local/bin/kr || true
fi

################################################################################
# Rust Tools
################################################################################

log_section "Installing Rust Tools"

if ! command -v cargo &> /dev/null; then
    log_info "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# RustScan
if ! command -v rustscan &> /dev/null; then
    log_info "Installing RustScan..."
    cargo install rustscan || log_warn "RustScan install failed"
fi

# Feroxbuster
if ! command -v feroxbuster &> /dev/null; then
    log_info "Installing Feroxbuster..."
    cargo install feroxbuster || log_warn "Feroxbuster install failed"
fi

################################################################################
# Python Tools from GitHub
################################################################################

log_section "Installing Python-based Tools"

# Sublist3r
log_info "Installing Sublist3r..."
git_clone_or_pull "https://github.com/aboul3la/Sublist3r.git" "$INSTALL_DIR/Sublist3r"
if [ -d "$INSTALL_DIR/Sublist3r" ]; then
    cd "$INSTALL_DIR/Sublist3r" && [ -f requirements.txt ] && "$PIP_CMD" install -r requirements.txt || true
    create_py_wrapper "sublist3r" "$INSTALL_DIR/Sublist3r/sublist3r.py" || true
fi

# Subdominator (RevoltSecurities)
log_info "Installing Subdominator..."
git_clone_or_pull "https://github.com/RevoltSecurities/Subdominator.git" "$INSTALL_DIR/Subdominator"
if [ -d "$INSTALL_DIR/Subdominator" ]; then
    cd "$INSTALL_DIR/Subdominator" && [ -f requirements.txt ] && "$PIP_CMD" install -r requirements.txt || true
    if [ -f "$INSTALL_DIR/Subdominator/subdominator.py" ]; then
        create_py_wrapper "subdominator" "$INSTALL_DIR/Subdominator/subdominator.py" || true
    elif [ -f "$INSTALL_DIR/Subdominator/Subdominator.py" ]; then
        create_py_wrapper "subdominator" "$INSTALL_DIR/Subdominator/Subdominator.py" || true
    fi
    ln -sfn "$INSTALL_DIR/Subdominator" "$INSTALL_DIR/SubDominator" || true
fi

# SubProber (RevoltSecurities)
log_info "Installing SubProber..."
git_clone_or_pull "https://github.com/RevoltSecurities/SubProber.git" "$INSTALL_DIR/SubProber"
if [ -d "$INSTALL_DIR/SubProber" ]; then
    cd "$INSTALL_DIR/SubProber" && [ -f requirements.txt ] && "$PIP_CMD" install -r requirements.txt || true
    if [ -f "$INSTALL_DIR/SubProber/subprober.py" ]; then
        create_py_wrapper "subprober" "$INSTALL_DIR/SubProber/subprober.py" || true
    elif [ -f "$INSTALL_DIR/SubProber/SubProber.py" ]; then
        create_py_wrapper "subprober" "$INSTALL_DIR/SubProber/SubProber.py" || true
    fi
    ln -sfn "$INSTALL_DIR/SubProber" "$INSTALL_DIR/subprober" || true
fi

# ShodanX (RevoltSecurities)
log_info "Installing ShodanX..."
git_clone_or_pull "https://github.com/RevoltSecurities/ShodanX.git" "$INSTALL_DIR/ShodanX"
if [ -d "$INSTALL_DIR/ShodanX" ]; then
    cd "$INSTALL_DIR/ShodanX" && [ -f requirements.txt ] && "$PIP_CMD" install -r requirements.txt || true
    if [ -f "$INSTALL_DIR/ShodanX/shodanx.py" ]; then
        create_py_wrapper "shodanx" "$INSTALL_DIR/ShodanX/shodanx.py" || true
    elif [ -f "$INSTALL_DIR/ShodanX/ShodanX.py" ]; then
        create_py_wrapper "shodanx" "$INSTALL_DIR/ShodanX/ShodanX.py" || true
    fi
    ln -sfn "$INSTALL_DIR/ShodanX" "$INSTALL_DIR/shodanx" || true
fi

# GoogleDorker (RevoltSecurities)
log_info "Installing GoogleDorker..."
git_clone_or_pull "https://github.com/RevoltSecurities/GoogleDorker.git" "$INSTALL_DIR/GoogleDorker"
if [ -d "$INSTALL_DIR/GoogleDorker" ]; then
    cd "$INSTALL_DIR/GoogleDorker" && [ -f requirements.txt ] && "$PIP_CMD" install -r requirements.txt || true
    if [ -f "$INSTALL_DIR/GoogleDorker/dorker.py" ]; then
        create_py_wrapper "dorker" "$INSTALL_DIR/GoogleDorker/dorker.py" || true
    elif [ -f "$INSTALL_DIR/GoogleDorker/GoogleDorker.py" ]; then
        create_py_wrapper "dorker" "$INSTALL_DIR/GoogleDorker/GoogleDorker.py" || true
    fi
fi

# SpideyX (RevoltSecurities)
log_info "Installing SpideyX..."
git_clone_or_pull "https://github.com/RevoltSecurities/SpideyX.git" "$INSTALL_DIR/SpideyX"
if [ -d "$INSTALL_DIR/SpideyX" ]; then
    cd "$INSTALL_DIR/SpideyX" && [ -f requirements.txt ] && "$PIP_CMD" install -r requirements.txt || true
    if [ -f "$INSTALL_DIR/SpideyX/spideyx.py" ]; then
        create_py_wrapper "spideyx" "$INSTALL_DIR/SpideyX/spideyx.py" || true
    elif [ -f "$INSTALL_DIR/SpideyX/SpideyX.py" ]; then
        create_py_wrapper "spideyx" "$INSTALL_DIR/SpideyX/SpideyX.py" || true
    fi
fi

# Dnsbruter (RevoltSecurities)
log_info "Installing Dnsbruter..."
git_clone_or_pull "https://github.com/RevoltSecurities/Dnsbruter.git" "$INSTALL_DIR/Dnsbruter"
if [ -d "$INSTALL_DIR/Dnsbruter" ]; then
    cd "$INSTALL_DIR/Dnsbruter" && [ -f requirements.txt ] && "$PIP_CMD" install -r requirements.txt || true
    if [ -f "$INSTALL_DIR/Dnsbruter/dnsbruter.py" ]; then
        create_py_wrapper "dnsbruter" "$INSTALL_DIR/Dnsbruter/dnsbruter.py" || true
    fi
    ln -sfn "$INSTALL_DIR/Dnsbruter" "$INSTALL_DIR/dnsbruter" || true
fi

# Cloud enumeration tools
log_info "Installing cloud_enum..."
git_clone_or_pull "https://github.com/initstring/cloud_enum.git" "$INSTALL_DIR/cloud_enum"
if [ -d "$INSTALL_DIR/cloud_enum" ]; then
    cd "$INSTALL_DIR/cloud_enum" && [ -f requirements.txt ] && "$PIP_CMD" install -r requirements.txt || true
    if [ -f "$INSTALL_DIR/cloud_enum/cloud_enum.py" ]; then
        create_py_wrapper "cloud_enum" "$INSTALL_DIR/cloud_enum/cloud_enum.py" || true
    fi
fi

log_info "Installing S3Scanner..."
git_clone_or_pull "https://github.com/sa7mon/S3Scanner.git" "$INSTALL_DIR/S3Scanner"
if [ -d "$INSTALL_DIR/S3Scanner" ]; then
    cd "$INSTALL_DIR/S3Scanner" && [ -f requirements.txt ] && "$PIP_CMD" install -r requirements.txt || true
    if [ -f "$INSTALL_DIR/S3Scanner/s3scanner.py" ]; then
        create_py_wrapper "s3scanner" "$INSTALL_DIR/S3Scanner/s3scanner.py" || true
    elif [ -f "$INSTALL_DIR/S3Scanner/S3Scanner.py" ]; then
        create_py_wrapper "s3scanner" "$INSTALL_DIR/S3Scanner/S3Scanner.py" || true
    fi
fi

log_info "Installing GCPBucketBrute..."
git_clone_or_pull "https://github.com/RhinoSecurityLabs/GCPBucketBrute.git" "$INSTALL_DIR/GCPBucketBrute"
if [ -d "$INSTALL_DIR/GCPBucketBrute" ]; then
    cd "$INSTALL_DIR/GCPBucketBrute" && [ -f requirements.txt ] && "$PIP_CMD" install -r requirements.txt || true
    if [ -f "$INSTALL_DIR/GCPBucketBrute/gcpbucketbrute.py" ]; then
        create_py_wrapper "gcpbucketbrute" "$INSTALL_DIR/GCPBucketBrute/gcpbucketbrute.py" || true
    fi
fi

# Dirsearch
log_info "Installing Dirsearch..."
git_clone_or_pull "https://github.com/maurosoria/dirsearch.git" "$INSTALL_DIR/dirsearch"
if [ -d "$INSTALL_DIR/dirsearch" ]; then
    cd "$INSTALL_DIR/dirsearch" && [ -f requirements.txt ] && "$PIP_CMD" install -r requirements.txt || true
    create_py_wrapper "dirsearch" "$INSTALL_DIR/dirsearch/dirsearch.py" || true
fi

# LinkFinder
log_info "Installing LinkFinder..."
git_clone_or_pull "https://github.com/GerbenJavado/LinkFinder.git" "$INSTALL_DIR/LinkFinder"
if [ -d "$INSTALL_DIR/LinkFinder" ]; then
    cd "$INSTALL_DIR/LinkFinder" && [ -f requirements.txt ] && "$PIP_CMD" install -r requirements.txt || true
    create_py_wrapper "linkfinder" "$INSTALL_DIR/LinkFinder/linkfinder.py" || true
fi

# SecretFinder
log_info "Installing SecretFinder..."
git_clone_or_pull "https://github.com/m4ll0k/SecretFinder.git" "$INSTALL_DIR/SecretFinder"
if [ -d "$INSTALL_DIR/SecretFinder" ]; then
    cd "$INSTALL_DIR/SecretFinder" && [ -f requirements.txt ] && "$PIP_CMD" install -r requirements.txt || true
    create_py_wrapper "secretfinder" "$INSTALL_DIR/SecretFinder/SecretFinder.py" || true
fi

# Corsy
log_info "Installing Corsy..."
git_clone_or_pull "https://github.com/s0md3v/Corsy.git" "$INSTALL_DIR/Corsy"
if [ -d "$INSTALL_DIR/Corsy" ]; then
    cd "$INSTALL_DIR/Corsy" && [ -f requirements.txt ] && "$PIP_CMD" install -r requirements.txt || true
    create_py_wrapper "corsy" "$INSTALL_DIR/Corsy/corsy.py" || true
fi

# XSStrike
log_info "Installing XSStrike..."
git_clone_or_pull "https://github.com/s0md3v/XSStrike.git" "$INSTALL_DIR/XSStrike"
if [ -d "$INSTALL_DIR/XSStrike" ]; then
    cd "$INSTALL_DIR/XSStrike" && [ -f requirements.txt ] && "$PIP_CMD" install -r requirements.txt || true
    create_py_wrapper "xsstrike" "$INSTALL_DIR/XSStrike/xsstrike.py" || true
fi

# Arjun (Python version)
log_info "Installing Arjun..."
"$PIP_CMD" install arjun || log_warn "Arjun install failed"

# altdns (subdomain permutation)
log_info "Installing altdns..."
"$PIP_CMD" install py-altdns || "$PIP_CMD" install altdns 2>/dev/null || log_warn "altdns install failed (try: pip install py-altdns)"

# WhatWeb (technology detection)
log_info "Installing WhatWeb..."
git_clone_or_pull "https://github.com/urbanadventurer/WhatWeb.git" "$INSTALL_DIR/WhatWeb"
if [ -d "$INSTALL_DIR/WhatWeb" ]; then
    cd "$INSTALL_DIR/WhatWeb" && bundle install 2>/dev/null || true
    if [ -f "$INSTALL_DIR/WhatWeb/whatweb" ]; then
        ln -sf "$INSTALL_DIR/WhatWeb/whatweb" /usr/local/bin/whatweb || true
    fi
fi

# GitHunt
log_info "Installing GitHunt..."
git_clone_or_pull "https://github.com/tillson/git-hound.git" "$INSTALL_DIR/GitHunt"
if [ -f "$INSTALL_DIR/GitHunt/githound.py" ]; then
    create_py_wrapper "githunt" "$INSTALL_DIR/GitHunt/githound.py" || true
fi

# Get Subsidiaries
log_info "Installing getSubsidiaries..."
git_clone_or_pull "https://github.com/Josue87/getSubsidiaries.git" "$INSTALL_DIR/getSubsidiaries"
if [ -f "$INSTALL_DIR/getSubsidiaries/getSubsidiaries.py" ]; then
    create_py_wrapper "getsubsidiaries" "$INSTALL_DIR/getSubsidiaries/getSubsidiaries.py" || true
fi

################################################################################
# Specialized Tools
################################################################################

log_section "Installing Specialized Tools"

# Gitleaks
log_info "Installing Gitleaks..."
GITLEAKS_VERSION="8.18.0"
wget -q https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz
tar -xzf gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz
mv gitleaks /usr/local/bin/
rm gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz

# TruffleHog
log_info "Installing TruffleHog..."
"$PIP_CMD" install trufflehog || log_warn "TruffleHog install failed"

# Gospider (SpideyX alternative)
log_info "Installing Gospider..."
go install -v github.com/jaeles-project/gospider@latest

# WPScan
log_info "Installing WPScan..."
gem install wpscan || log_warn "WPScan install failed"

# Wapiti
log_info "Installing Wapiti..."
"$PIP_CMD" install wapiti3 || log_warn "Wapiti install failed"

# CMSmap
log_info "Installing CMSmap..."
git_clone_or_pull "https://github.com/Dionach/CMSmap.git" "$INSTALL_DIR/CMSmap"
if [ -f "$INSTALL_DIR/CMSmap/cmsmap.py" ]; then
    create_py_wrapper "cmsmap" "$INSTALL_DIR/CMSmap/cmsmap.py" || true
fi

# Retire.js
log_info "Installing Retire.js..."
npm install -g retire || log_warn "Retire.js install failed"

# testssl.sh
log_info "Installing testssl.sh..."
git_clone_or_pull "https://github.com/drwetter/testssl.sh.git" "$INSTALL_DIR/testssl.sh"
if [ -f "$INSTALL_DIR/testssl.sh/testssl.sh" ]; then
    ln -sf "$INSTALL_DIR/testssl.sh/testssl.sh" /usr/local/bin/testssl.sh || true
fi

# SSLyze
log_info "Installing SSLyze..."
"$PIP_CMD" install sslyze || log_warn "SSLyze install failed"

# Shodan CLI
log_info "Installing Shodan CLI..."
"$PIP_CMD" install shodan || log_warn "Shodan install failed"

# Censys CLI
log_info "Installing Censys CLI..."
"$PIP_CMD" install censys || log_warn "Censys install failed"

# ct-monitor (optional)
log_info "Installing ct-monitor..."
"$PIP_CMD" install ct-monitor || log_warn "ct-monitor install failed"

# VirusTotal CLI / requests (for scripts that use VT_API_KEY)
# HaveIBeenPwned, AbuseIPDB, etc. are typically used via curl in bash; keys go in .env

# Newman (Postman CLI)
log_info "Installing Newman..."
npm install -g newman || log_warn "Newman install failed"

# git-secrets
log_info "Installing git-secrets..."
git_clone_or_pull "https://github.com/awslabs/git-secrets.git" "$INSTALL_DIR/git-secrets"
if [ -d "$INSTALL_DIR/git-secrets" ]; then
    cd "$INSTALL_DIR/git-secrets" && make install || true
fi

################################################################################
# Wordlists
################################################################################

log_section "Installing Wordlists"

if [ ! -d "/usr/share/seclists" ]; then
    log_info "Installing SecLists..."
    GIT_TERMINAL_PROMPT=0 git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists || log_warn "Failed to clone SecLists"
else
    log_info "SecLists already installed"
fi

if [ ! -d "/usr/share/wordlists" ]; then
    mkdir -p /usr/share/wordlists
fi

################################################################################
# Configuration
################################################################################

log_section "Setting up Configuration"

# Add Go binaries to PATH
if ! grep -q "GOPATH" /etc/profile; then
    echo "export GOPATH=$HOME/go" >> /etc/profile
    echo "export PATH=\$PATH:\$GOPATH/bin:/usr/local/go/bin" >> /etc/profile
fi

# Update Nuclei templates
if command -v nuclei &> /dev/null; then
    log_info "Updating Nuclei templates..."
    nuclei -update-templates || log_warn "Failed to update Nuclei templates"
fi

################################################################################
# Verification
################################################################################

log_section "Verifying Installation"

TOOLS=(
    "subfinder" "assetfinder" "amass"
    "asnmap" "mapcidr" "dnsgen"
    "dnsx" "httpx"
    "gau" "waybackurls" "hakrawler" "katana"
    "ffuf" "feroxbuster"
    "nuclei" "dalfox"
    "subjack" "gitleaks"
    "nmap" "sqlmap" "nikto"
    "subdominator" "subprober" "shodanx" "dorker" "spideyx" "dnsbruter"
    "cloud_enum" "s3scanner" "gcpbucketbrute" "goblob" "ct-monitor"
    "skipfish" "p0f"
)

INSTALLED=0
MISSING=0

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        log_info "$tool installed ✓"
        ((INSTALLED++))
    else
        log_warn "$tool not found ✗"
        ((MISSING++))
    fi
done

echo ""
log_section "Installation Summary"
echo "Installed: $INSTALLED"
echo "Missing: $MISSING"

if [ $MISSING -gt 0 ]; then
    log_warn "Some tools failed to install. Please install them manually."
fi

################################################################################
# API Keys Setup
################################################################################

log_section "API Keys Configuration"

cat << 'EOF'

ReconX requires API keys for certain services. Please configure them:

1. Copy the env template and add your keys:

   cp .env.example .env
   # Edit .env - it lists all API keys (Phase 1-5, threat intel, optional).

   # Examples (see .env.example for full list):
   # SHODAN_API_KEY=...
   # CENSYS_API_ID=...  CENSYS_API_SECRET=...
   # GITHUB_TOKEN=...
   # SECURITYTRAILS_API_KEY=...
   # VT_API_KEY=...  ABUSEIPDB_API_KEY=...  OTX_API_KEY=...

2. Load env before running ReconX (or run via python which loads .env automatically):
   source .env
   python3 reconx.py -t example.com

EOF

log_section "Installation Complete!"

cat << 'EOF'

To get started with ReconX:

1. cd to the ReconX directory
2. Run: python3 reconx.py -t example.com
3. For help: python3 reconx.py -h

Happy Hunting! 🎯

EOF

exit 0
