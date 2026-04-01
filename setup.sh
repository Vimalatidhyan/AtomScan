#!/usr/bin/env bash
# ==============================================================================
# Technieum — Quick Environment Verifier
# Run after install.sh to confirm the environment is ready.
# Usage: bash setup.sh
# ==============================================================================

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; }
info() { echo -e "${BLUE}[*]${NC} $*"; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${BLUE}"
cat << "EOF"
╦═╗╔═╗╔═╗╔═╗╔╗╔╦ ╦
╠╦╝║╣ ║  ║ ║║║║╔╩╦╝
╩╚═╚═╝╚═╝╚═╝╝╚╝╩ ╚═
Quick Environment Verifier
EOF
echo -e "${NC}"

# ── Ensure we are in the correct directory ────────────────────────────────────
if [[ ! -f "technieum.py" ]]; then
    err "Please run this script from the Technieum project directory."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
ISSUES=0

# ── Virtual environment ───────────────────────────────────────────────────────
info "Checking Python virtual environment..."
if [[ -d "$VENV_DIR" ]]; then
    ok "Virtual environment found: $VENV_DIR"
else
    warn "Virtual environment not found at $VENV_DIR"
    warn "Run: python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt"
    ((ISSUES++))
fi

# Determine which Python/pip to use
if [[ -f "$VENV_DIR/bin/python3" ]]; then
    PYTHON="$VENV_DIR/bin/python3"
    PIP="$VENV_DIR/bin/pip"
else
    PYTHON="python3"
    PIP="pip3"
    warn "Using system Python — consider activating the venv: source .venv/bin/activate"
fi

# ── Python version ────────────────────────────────────────────────────────────
info "Checking Python version..."
PY_VERSION=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$("$PYTHON" -c "import sys; print(sys.version_info.major)")
PY_MINOR=$("$PYTHON" -c "import sys; print(sys.version_info.minor)")

if [[ "$PY_MAJOR" -ge 3 && "$PY_MINOR" -ge 11 ]]; then
    ok "Python $PY_VERSION (OK — requires 3.11+)"
else
    err "Python $PY_VERSION is too old — Technieum requires Python 3.11+"
    ((ISSUES++))
fi

# ── Python packages ───────────────────────────────────────────────────────────
info "Checking Python packages..."
REQUIRED_PACKAGES=(fastapi uvicorn sqlalchemy pydantic aiohttp httpx networkx dnspython yaml dotenv)
MISSING_PKGS=()

for pkg in "${REQUIRED_PACKAGES[@]}"; do
    module="${pkg}"
    # Map package install name → import name where they differ
    case "$pkg" in
        yaml)      module="yaml" ;;
        dotenv)    module="dotenv" ;;
        aiohttp)   module="aiohttp" ;;
    esac
    if ! "$PYTHON" -c "import $module" 2>/dev/null; then
        MISSING_PKGS+=("$pkg")
    fi
done

if [[ ${#MISSING_PKGS[@]} -eq 0 ]]; then
    ok "All required Python packages present"
else
    warn "Missing Python packages: ${MISSING_PKGS[*]}"
    warn "Run: source .venv/bin/activate && pip install -r requirements.txt"
    ((ISSUES++))
fi

# ── Critical system tools ─────────────────────────────────────────────────────
info "Checking critical system tools..."
CRITICAL_TOOLS=(python3 bash sqlite3)
MISSING_CRITICAL=()

for tool in "${CRITICAL_TOOLS[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
        MISSING_CRITICAL+=("$tool")
    fi
done

if [[ ${#MISSING_CRITICAL[@]} -eq 0 ]]; then
    ok "All critical tools found (python3, bash, sqlite3)"
else
    err "Missing critical tools: ${MISSING_CRITICAL[*]}"
    ((ISSUES++))
fi

# ── Go binary tools ───────────────────────────────────────────────────────────
info "Checking reconnaissance tools..."
RECON_TOOLS=(subfinder httpx nuclei dnsx gau ffuf nmap)
MISSING_RECON=()

for tool in "${RECON_TOOLS[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
        MISSING_RECON+=("$tool")
    fi
done

if [[ ${#MISSING_RECON[@]} -eq 0 ]]; then
    ok "All core reconnaissance tools found"
else
    warn "Missing reconnaissance tools: ${MISSING_RECON[*]}"
    warn "Run: sudo bash install.sh"
    ((ISSUES++))
fi

# ── Go environment ────────────────────────────────────────────────────────────
info "Checking Go environment..."
if command -v go &>/dev/null; then
    GO_VER=$(go version | awk '{print $3}')
    ok "Go found: $GO_VER"
    if [[ -z "${GOPATH:-}" ]]; then
        warn "GOPATH not set — add to ~/.bashrc:"
        echo "    export GOPATH=\$HOME/go"
        echo "    export PATH=\$PATH:\$GOPATH/bin"
    fi
else
    warn "Go not found — required for nuclei, subfinder, httpx, etc."
    warn "Run: sudo bash install.sh"
    ((ISSUES++))
fi

# ── Directories ───────────────────────────────────────────────────────────────
info "Checking required directories..."
for d in output logs; do
    if [[ ! -d "$d" ]]; then
        mkdir -p "$d"
        ok "Created directory: $d"
    else
        ok "Directory present: $d"
    fi
done

# ── Module scripts executable ─────────────────────────────────────────────────
info "Checking module script permissions..."
if ls modules/*.sh &>/dev/null; then
    chmod +x modules/*.sh
    ok "Module scripts are executable"
else
    warn "No bash modules found in modules/ — this is OK if using API-only mode"
fi

# ── Environment file ──────────────────────────────────────────────────────────
info "Checking environment configuration..."
if [[ -f ".env" ]]; then
    ok ".env file present"
    # Quick check for placeholder values
    UNCONFIGURED=$(grep -c "your_key_here\|change_me" .env 2>/dev/null || true)
    if [[ "$UNCONFIGURED" -gt 0 ]]; then
        warn "$UNCONFIGURED API key(s) still set to placeholder — edit .env to add real keys"
    fi
elif [[ -f ".env.example" ]]; then
    warn ".env not found — creating from .env.example"
    cp .env.example .env
    warn "Edit .env and replace placeholder values with your actual API keys"
    ((ISSUES++))
else
    warn "No .env or .env.example found — API keys will not be available"
    warn "See README.md for the full API key reference"
    ((ISSUES++))
fi

# ── Database connectivity ─────────────────────────────────────────────────────
info "Testing database connectivity..."
if "$PYTHON" -c "
import os, sys
sys.path.insert(0, '.')
try:
    from db.database import DatabaseManager
    db = DatabaseManager('test_setup.db')
    print('ok')
except Exception as e:
    print(f'fail:{e}')
" 2>/dev/null | grep -q "^ok"; then
    ok "Database layer OK"
    rm -f test_setup.db test_setup.db-shm test_setup.db-wal
else
    warn "Database self-test failed — check backend/db/ and requirements"
    ((ISSUES++))
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
if [[ $ISSUES -eq 0 ]]; then
    ok "Environment is ready. No issues found."
else
    warn "$ISSUES issue(s) found — see warnings above."
fi
echo ""
echo "Next steps:"
echo "  1. Activate venv:          source .venv/bin/activate"
echo "  2. Edit API keys:          nano .env"
echo "  3. Run a scan:             python3 technieum.py -t example.com"
echo "  4. Start the API server:   python3 -m uvicorn backend.api.server:app --port 8000"
echo "  5. Open the dashboard:     http://localhost:8000/"
echo ""
echo "For full documentation see README.md"
echo "══════════════════════════════════════════════════════"

exit 0
