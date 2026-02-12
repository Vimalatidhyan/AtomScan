#!/bin/bash
################################################################################
# ReconX Quick Setup
# Prepares the environment for running ReconX
################################################################################

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
cat << "EOF"
╦═╗╔═╗╔═╗╔═╗╔╗╔╦ ╦
╠╦╝║╣ ║  ║ ║║║║╔╩╦╝
╩╚═╚═╝╚═╝╚═╝╝╚╝╩ ╚═
Quick Setup Script
EOF
echo -e "${NC}"

log_info() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Check if running in ReconX directory
if [ ! -f "reconx.py" ]; then
    echo "Error: Please run this script from the ReconX directory"
    exit 1
fi

log_info "Setting up ReconX environment..."

# Create directories
log_info "Creating directories..."
mkdir -p output logs

# Install Python requirements
if [ -f "requirements.txt" ]; then
    log_info "Installing Python requirements..."
    pip3 install -r requirements.txt 2>/dev/null || log_warn "Some Python packages may not have installed"
fi

# Setup environment file (all API keys wired from .env)
if [ ! -f ".env.example" ]; then
    log_warn ".env.example not found; create .env and add API keys manually"
elif [ ! -f ".env" ]; then
    log_info "Creating .env from .env.example..."
    cp .env.example .env
    log_warn "Edit .env and add your API keys (see comments in .env.example for sources)"
else
    log_info ".env already exists (API keys loaded from here)"
fi

# Make scripts executable
log_info "Making scripts executable..."
chmod +x reconx.py query.py install.sh modules/*.sh 2>/dev/null || true

# Check for critical tools
log_info "Checking for critical tools..."

CRITICAL_TOOLS=("python3" "bash" "sqlite3")
MISSING=()

for tool in "${CRITICAL_TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        MISSING+=("$tool")
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    log_warn "Missing critical tools: ${MISSING[*]}"
    log_warn "Please run install.sh to install all required tools"
else
    log_info "All critical tools found"
fi

# Check for reconnaissance tools
log_info "Checking for reconnaissance tools..."

RECON_TOOLS=("subfinder" "amass" "httpx" "nuclei" "nmap")
RECON_MISSING=0

for tool in "${RECON_TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        ((RECON_MISSING++))
    fi
done

if [ $RECON_MISSING -gt 0 ]; then
    log_warn "Missing $RECON_MISSING reconnaissance tools"
    log_warn "Run 'sudo bash install.sh' to install all tools"
else
    log_info "Core reconnaissance tools found"
fi

# Test database
log_info "Testing database..."
python3 -c "from db.database import DatabaseManager; db = DatabaseManager('test_setup.db'); print('✓ Database OK')" && rm -f test_setup.db* || log_warn "Database test failed"

# Check Go environment
if command -v go &> /dev/null; then
    log_info "Go found: $(go version)"
    if [ -z "$GOPATH" ]; then
        log_warn "GOPATH not set. Add to ~/.bashrc:"
        echo "  export GOPATH=\$HOME/go"
        echo "  export PATH=\$PATH:\$GOPATH/bin"
    fi
else
    log_warn "Go not found - required for many tools"
fi

# Summary
echo ""
log_info "Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Edit .env and add API keys (see .env.example for full list)"
echo "  2. Source before running: source .env   (or export vars)"
if [ $RECON_MISSING -gt 0 ]; then
    echo "  3. Install tools: sudo bash install.sh"
    echo "  4. Run ReconX: python3 reconx.py -t example.com"
else
    echo "  3. Run ReconX: python3 reconx.py -t example.com"
fi
echo ""
echo "For help: python3 reconx.py -h"
echo ""

exit 0
