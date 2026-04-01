#!/usr/bin/env bash
# Install all missing Technieum recon tools in WSL
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; }

# ── Go setup ──────────────────────────────────────────────────────────────────
GO_BIN="/usr/lib/go-1.24/bin/go"
if [[ ! -f "$GO_BIN" ]]; then
    # Fallback search
    GO_BIN=$(find /usr/local/go/bin /usr/lib -name 'go' -type f 2>/dev/null | head -1)
fi

if [[ -z "$GO_BIN" || ! -f "$GO_BIN" ]]; then
    err "Go not found. Install Go first."
    exit 1
fi

export GOROOT=$(dirname $(dirname "$GO_BIN"))
export GOPATH="${HOME}/go"
export PATH="${GOPATH}/bin:${GOROOT}/bin:${PATH}"
ok "Using Go: $("$GO_BIN" version)"

mkdir -p "${GOPATH}/bin"

go_install() {
    local pkg="$1"
    local bin="${2:-$(basename "${pkg%%@*}")}"
    if command -v "$bin" &>/dev/null; then
        ok "$bin already installed ($(command -v "$bin"))"
        return
    fi
    echo -e "${YELLOW}[~]${NC} Installing $bin..."
    if "$GO_BIN" install "$pkg" 2>&1; then
        ok "$bin installed"
    else
        warn "$bin install failed (skipping)"
    fi
}

# ── Go tools ──────────────────────────────────────────────────────────────────
echo ""
echo "=== Installing Go tools ==="

go_install "github.com/lc/gau/v2/cmd/gau@latest"          "gau"
go_install "github.com/tomnomnom/waybackurls@latest"       "waybackurls"
go_install "github.com/hakluke/hakrawler@latest"           "hakrawler"
go_install "github.com/haccer/subjack@latest"              "subjack"
go_install "github.com/Ice3man543/SubOver@latest"          "SubOver"
go_install "github.com/gitleaks/gitleaks/v8@latest"        "gitleaks"
go_install "github.com/jaeles-project/gospider@latest"     "gospider"
go_install "github.com/trufflesecurity/trufflehog/v3@latest" "trufflehog"

# ── git-secrets ───────────────────────────────────────────────────────────────
echo ""
echo "=== Installing git-secrets ==="
if command -v git-secrets &>/dev/null; then
    ok "git-secrets already installed"
else
    echo -e "${YELLOW}[~]${NC} Installing git-secrets..."
    TMPDIR=$(mktemp -d)
    if git clone --depth 1 https://github.com/awslabs/git-secrets.git "$TMPDIR/git-secrets" 2>/dev/null; then
        cd "$TMPDIR/git-secrets"
        make install PREFIX=/usr/local 2>/dev/null || sudo make install PREFIX=/usr/local 2>/dev/null || warn "git-secrets make install failed"
        cd - >/dev/null
        command -v git-secrets &>/dev/null && ok "git-secrets installed" || warn "git-secrets install failed"
    else
        warn "git-secrets clone failed — skipping"
    fi
    rm -rf "$TMPDIR"
fi

# ── GitHunt ───────────────────────────────────────────────────────────────────
echo ""
echo "=== Installing GitHunt ==="
if [[ -f /opt/GitHunt/githunt.py ]] || command -v githunt &>/dev/null; then
    ok "GitHunt already installed"
else
    echo -e "${YELLOW}[~]${NC} Cloning GitHunt..."
    if git clone --depth 1 https://github.com/HightechSec/git-scanner.git /opt/GitHunt 2>/dev/null; then
        ok "GitHunt cloned to /opt/GitHunt"
    else
        warn "GitHunt clone failed — GITHUB_TOKEN not set warning will persist (optional tool)"
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== Tool Check ==="
for tool in gau waybackurls hakrawler subjack SubOver gitleaks gospider trufflehog git-secrets; do
    if command -v "$tool" &>/dev/null; then
        ok "$tool: $(command -v "$tool")"
    else
        warn "$tool: NOT FOUND"
    fi
done

echo ""
ok "Done. Make sure ${GOPATH}/bin is in your PATH:"
echo "  export PATH=\"\${HOME}/go/bin:\${PATH}\""
echo "  Add to ~/.bashrc for persistence."
