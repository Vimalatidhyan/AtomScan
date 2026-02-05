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
# Python Dependencies
################################################################################

log_section "Installing Python Dependencies"

pip3 install --upgrade pip
pip3 install \
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

# DNS Tools
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

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
git clone https://github.com/assetnote/kiterunner.git "$TOOLS_DIR/kiterunner" 2>/dev/null || true
cd "$TOOLS_DIR/kiterunner" && make build && ln -sf "$TOOLS_DIR/kiterunner/dist/kr" /usr/local/bin/kr || true

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
git clone https://github.com/aboul3la/Sublist3r.git "$INSTALL_DIR/Sublist3r" 2>/dev/null || (cd "$INSTALL_DIR/Sublist3r" && git pull)
cd "$INSTALL_DIR/Sublist3r" && pip3 install -r requirements.txt || true

# Subdominator (RevoltSecurities)
log_info "Installing Subdominator..."
git clone https://github.com/RevoltSecurities/Subdominator.git "$INSTALL_DIR/Subdominator" 2>/dev/null || (cd "$INSTALL_DIR/Subdominator" && git pull)
cd "$INSTALL_DIR/Subdominator" && [ -f requirements.txt ] && pip3 install -r requirements.txt || true
if [ -f "$INSTALL_DIR/Subdominator/subdominator.py" ]; then
    ln -sf "$INSTALL_DIR/Subdominator/subdominator.py" /usr/local/bin/subdominator || true
elif [ -f "$INSTALL_DIR/Subdominator/Subdominator.py" ]; then
    ln -sf "$INSTALL_DIR/Subdominator/Subdominator.py" /usr/local/bin/subdominator || true
fi
ln -sfn "$INSTALL_DIR/Subdominator" "$INSTALL_DIR/SubDominator" || true

# SubProber (RevoltSecurities)
log_info "Installing SubProber..."
git clone https://github.com/RevoltSecurities/SubProber.git "$INSTALL_DIR/SubProber" 2>/dev/null || (cd "$INSTALL_DIR/SubProber" && git pull)
cd "$INSTALL_DIR/SubProber" && [ -f requirements.txt ] && pip3 install -r requirements.txt || true
if [ -f "$INSTALL_DIR/SubProber/subprober.py" ]; then
    ln -sf "$INSTALL_DIR/SubProber/subprober.py" /usr/local/bin/subprober || true
elif [ -f "$INSTALL_DIR/SubProber/SubProber.py" ]; then
    ln -sf "$INSTALL_DIR/SubProber/SubProber.py" /usr/local/bin/subprober || true
fi
ln -sfn "$INSTALL_DIR/SubProber" "$INSTALL_DIR/subprober" || true

# ShodanX (RevoltSecurities)
log_info "Installing ShodanX..."
git clone https://github.com/RevoltSecurities/ShodanX.git "$INSTALL_DIR/ShodanX" 2>/dev/null || (cd "$INSTALL_DIR/ShodanX" && git pull)
cd "$INSTALL_DIR/ShodanX" && [ -f requirements.txt ] && pip3 install -r requirements.txt || true
if [ -f "$INSTALL_DIR/ShodanX/shodanx.py" ]; then
    ln -sf "$INSTALL_DIR/ShodanX/shodanx.py" /usr/local/bin/shodanx || true
elif [ -f "$INSTALL_DIR/ShodanX/ShodanX.py" ]; then
    ln -sf "$INSTALL_DIR/ShodanX/ShodanX.py" /usr/local/bin/shodanx || true
fi
ln -sfn "$INSTALL_DIR/ShodanX" "$INSTALL_DIR/shodanx" || true

# GoogleDorker (RevoltSecurities)
log_info "Installing GoogleDorker..."
git clone https://github.com/RevoltSecurities/GoogleDorker.git "$INSTALL_DIR/GoogleDorker" 2>/dev/null || (cd "$INSTALL_DIR/GoogleDorker" && git pull)
cd "$INSTALL_DIR/GoogleDorker" && [ -f requirements.txt ] && pip3 install -r requirements.txt || true
if [ -f "$INSTALL_DIR/GoogleDorker/dorker.py" ]; then
    ln -sf "$INSTALL_DIR/GoogleDorker/dorker.py" /usr/local/bin/dorker || true
elif [ -f "$INSTALL_DIR/GoogleDorker/GoogleDorker.py" ]; then
    ln -sf "$INSTALL_DIR/GoogleDorker/GoogleDorker.py" /usr/local/bin/dorker || true
fi

# SpideyX (RevoltSecurities)
log_info "Installing SpideyX..."
git clone https://github.com/RevoltSecurities/SpideyX.git "$INSTALL_DIR/SpideyX" 2>/dev/null || (cd "$INSTALL_DIR/SpideyX" && git pull)
cd "$INSTALL_DIR/SpideyX" && [ -f requirements.txt ] && pip3 install -r requirements.txt || true
if [ -f "$INSTALL_DIR/SpideyX/spideyx.py" ]; then
    ln -sf "$INSTALL_DIR/SpideyX/spideyx.py" /usr/local/bin/spideyx || true
elif [ -f "$INSTALL_DIR/SpideyX/SpideyX.py" ]; then
    ln -sf "$INSTALL_DIR/SpideyX/SpideyX.py" /usr/local/bin/spideyx || true
fi

# Dnsbruter (RevoltSecurities)
log_info "Installing Dnsbruter..."
git clone https://github.com/RevoltSecurities/Dnsbruter.git "$INSTALL_DIR/Dnsbruter" 2>/dev/null || (cd "$INSTALL_DIR/Dnsbruter" && git pull)
cd "$INSTALL_DIR/Dnsbruter" && [ -f requirements.txt ] && pip3 install -r requirements.txt || true
if [ -f "$INSTALL_DIR/Dnsbruter/dnsbruter.py" ]; then
    ln -sf "$INSTALL_DIR/Dnsbruter/dnsbruter.py" /usr/local/bin/dnsbruter || true
fi
ln -sfn "$INSTALL_DIR/Dnsbruter" "$INSTALL_DIR/dnsbruter" || true

# Dirsearch
log_info "Installing Dirsearch..."
git clone https://github.com/maurosoria/dirsearch.git "$INSTALL_DIR/dirsearch" 2>/dev/null || (cd "$INSTALL_DIR/dirsearch" && git pull)
cd "$INSTALL_DIR/dirsearch" && pip3 install -r requirements.txt || true
ln -sf "$INSTALL_DIR/dirsearch/dirsearch.py" /usr/local/bin/dirsearch || true

# LinkFinder
log_info "Installing LinkFinder..."
git clone https://github.com/GerbenJavado/LinkFinder.git "$INSTALL_DIR/LinkFinder" 2>/dev/null || (cd "$INSTALL_DIR/LinkFinder" && git pull)
cd "$INSTALL_DIR/LinkFinder" && pip3 install -r requirements.txt || true
ln -sf "$INSTALL_DIR/LinkFinder/linkfinder.py" /usr/local/bin/linkfinder || true

# SecretFinder
log_info "Installing SecretFinder..."
git clone https://github.com/m4ll0k/SecretFinder.git "$INSTALL_DIR/SecretFinder" 2>/dev/null || (cd "$INSTALL_DIR/SecretFinder" && git pull)
cd "$INSTALL_DIR/SecretFinder" && pip3 install -r requirements.txt || true

# Corsy
log_info "Installing Corsy..."
git clone https://github.com/s0md3v/Corsy.git "$INSTALL_DIR/Corsy" 2>/dev/null || (cd "$INSTALL_DIR/Corsy" && git pull)
cd "$INSTALL_DIR/Corsy" && pip3 install -r requirements.txt || true

# XSStrike
log_info "Installing XSStrike..."
git clone https://github.com/s0md3v/XSStrike.git "$INSTALL_DIR/XSStrike" 2>/dev/null || (cd "$INSTALL_DIR/XSStrike" && git pull)
cd "$INSTALL_DIR/XSStrike" && pip3 install -r requirements.txt || true

# Arjun (Python version)
log_info "Installing Arjun..."
pip3 install arjun || log_warn "Arjun install failed"

# GitHunt
log_info "Installing GitHunt..."
git clone https://github.com/tillson/git-hound.git "$INSTALL_DIR/GitHunt" 2>/dev/null || (cd "$INSTALL_DIR/GitHunt" && git pull)

# Get Subsidiaries
log_info "Installing getSubsidiaries..."
git clone https://github.com/Josue87/getSubsidiaries.git "$INSTALL_DIR/getSubsidiaries" 2>/dev/null || (cd "$INSTALL_DIR/getSubsidiaries" && git pull)

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
pip3 install trufflehog || log_warn "TruffleHog install failed"

# Gospider (SpideyX alternative)
log_info "Installing Gospider..."
go install -v github.com/jaeles-project/gospider@latest

# WPScan
log_info "Installing WPScan..."
gem install wpscan || log_warn "WPScan install failed"

# Wapiti
log_info "Installing Wapiti..."
pip3 install wapiti3 || log_warn "Wapiti install failed"

# CMSmap
log_info "Installing CMSmap..."
git clone https://github.com/Dionach/CMSmap.git "$INSTALL_DIR/CMSmap" 2>/dev/null || (cd "$INSTALL_DIR/CMSmap" && git pull)
ln -sf "$INSTALL_DIR/CMSmap/cmsmap.py" /usr/local/bin/cmsmap || true

# Retire.js
log_info "Installing Retire.js..."
npm install -g retire || log_warn "Retire.js install failed"

# testssl.sh
log_info "Installing testssl.sh..."
git clone --depth 1 https://github.com/drwetter/testssl.sh.git "$INSTALL_DIR/testssl.sh" 2>/dev/null || (cd "$INSTALL_DIR/testssl.sh" && git pull)
ln -sf "$INSTALL_DIR/testssl.sh/testssl.sh" /usr/local/bin/testssl.sh || true

# SSLyze
log_info "Installing SSLyze..."
pip3 install sslyze || log_warn "SSLyze install failed"

# Shodan CLI
log_info "Installing Shodan CLI..."
pip3 install shodan || log_warn "Shodan install failed"

# Censys CLI
log_info "Installing Censys CLI..."
pip3 install censys || log_warn "Censys install failed"

# Newman (Postman CLI)
log_info "Installing Newman..."
npm install -g newman || log_warn "Newman install failed"

# git-secrets
log_info "Installing git-secrets..."
git clone https://github.com/awslabs/git-secrets.git "$INSTALL_DIR/git-secrets" 2>/dev/null || (cd "$INSTALL_DIR/git-secrets" && git pull)
cd "$INSTALL_DIR/git-secrets" && make install || true

################################################################################
# Wordlists
################################################################################

log_section "Installing Wordlists"

if [ ! -d "/usr/share/seclists" ]; then
    log_info "Installing SecLists..."
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists
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
    "dnsx" "httpx"
    "gau" "waybackurls" "hakrawler" "katana"
    "ffuf" "feroxbuster"
    "nuclei" "dalfox"
    "subjack" "gitleaks"
    "nmap" "sqlmap" "nikto"
    "subdominator" "subprober" "shodanx" "dorker" "spideyx" "dnsbruter"
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

1. Create a .env file in the ReconX directory:

   # Shodan
   export SHODAN_API_KEY="your_shodan_key"

   # Censys
   export CENSYS_API_ID="your_censys_id"
   export CENSYS_API_SECRET="your_censys_secret"

   # GitHub
   export GITHUB_TOKEN="your_github_token"

   # SecurityTrails
   export SECURITYTRAILS_API_KEY="your_securitytrails_key"

   # Pastebin
   export PASTEBIN_API_KEY="your_pastebin_key"

2. Source the file before running ReconX:
   source .env

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
