#!/usr/bin/env bash
# Install gitleaks, trufflehog, git-secrets, GitHunt via pre-built binaries / apt
set -e
GOBIN=/home/Vimalatithyan/go/bin
mkdir -p "$GOBIN"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
info() { echo -e "[~] $*"; }

# ── 1. gitleaks — GitHub release binary ──────────────────────────────────────
if command -v gitleaks &>/dev/null; then
    ok "gitleaks already installed: $(command -v gitleaks)"
else
    info "Downloading gitleaks binary..."
    GL_VER="8.21.2"
    GL_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GL_VER}/gitleaks_${GL_VER}_linux_x64.tar.gz"
    TMP=$(mktemp -d)
    if curl -fsSL "$GL_URL" -o "$TMP/gitleaks.tar.gz" 2>&1; then
        tar -xzf "$TMP/gitleaks.tar.gz" -C "$TMP"
        cp "$TMP/gitleaks" "$GOBIN/gitleaks"
        chmod +x "$GOBIN/gitleaks"
        ok "gitleaks ${GL_VER} installed to $GOBIN/gitleaks"
    else
        warn "gitleaks binary download failed"
    fi
    rm -rf "$TMP"
fi

# ── 2. trufflehog — GitHub install script ────────────────────────────────────
if command -v trufflehog &>/dev/null; then
    ok "trufflehog already installed: $(command -v trufflehog)"
else
    info "Downloading trufflehog binary..."
    TH_VER=$(curl -fsSL "https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest" 2>/dev/null | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/' | head -1)
    TH_VER="${TH_VER:-3.82.0}"
    TH_URL="https://github.com/trufflesecurity/trufflehog/releases/download/v${TH_VER}/trufflehog_${TH_VER}_linux_amd64.tar.gz"
    TMP=$(mktemp -d)
    if curl -fsSL "$TH_URL" -o "$TMP/trufflehog.tar.gz" 2>&1; then
        tar -xzf "$TMP/trufflehog.tar.gz" -C "$TMP"
        cp "$TMP/trufflehog" "$GOBIN/trufflehog"
        chmod +x "$GOBIN/trufflehog"
        ok "trufflehog ${TH_VER} installed to $GOBIN/trufflehog"
    else
        warn "trufflehog binary download failed"
    fi
    rm -rf "$TMP"
fi

# ── 3. git-secrets — make install (needs sudo) ───────────────────────────────
if command -v git-secrets &>/dev/null; then
    ok "git-secrets already installed: $(command -v git-secrets)"
else
    info "Installing git-secrets..."
    TMP=$(mktemp -d)
    if git clone --depth 1 https://github.com/awslabs/git-secrets.git "$TMP/git-secrets" 2>&1; then
        # Try install without sudo to user-local prefix first
        cd "$TMP/git-secrets"
        if make install PREFIX="$HOME/.local" 2>&1; then
            # Add to PATH if not there
            export PATH="$HOME/.local/bin:$PATH"
            ok "git-secrets installed to $HOME/.local/bin"
        else
            warn "git-secrets make install failed — copy manually: cp $TMP/git-secrets/git-secrets $GOBIN/"
            cp "$TMP/git-secrets/git-secrets" "$GOBIN/git-secrets" 2>/dev/null && ok "git-secrets copied to $GOBIN" || warn "git-secrets copy failed"
        fi
        cd - >/dev/null
    else
        warn "git-secrets clone failed"
    fi
    rm -rf "$TMP"
fi

# ── 4. GitHunt — clone to writable location ─────────────────────────────────
GITHUNT_DIR="$HOME/tools/GitHunt"
if [[ -f "$GITHUNT_DIR/githunt.py" ]]; then
    ok "GitHunt already present at $GITHUNT_DIR"
elif [[ -f /opt/GitHunt/githunt.py ]]; then
    ok "GitHunt present at /opt/GitHunt"
else
    info "Cloning GitHunt..."
    mkdir -p "$HOME/tools"
    if git clone --depth 1 https://github.com/HightechSec/git-scanner.git "$GITHUNT_DIR" 2>&1; then
        ok "GitHunt cloned to $GITHUNT_DIR"
        # Update module reference in module check
        echo "Note: GitHunt is at $GITHUNT_DIR/githunt.py"
    else
        warn "GitHunt clone failed (optional tool)"
    fi
fi

# ── Final status ─────────────────────────────────────────────────────────────
echo ""
echo "=== Final tool check ==="
export PATH="$HOME/.local/bin:$GOBIN:$PATH"
for t in gau waybackurls hakrawler subjack SubOver gitleaks gospider trufflehog git-secrets; do
    command -v "$t" &>/dev/null && ok "$t: $(command -v $t)" || warn "MISSING: $t"
done
[[ -f /opt/GitHunt/githunt.py ]] && ok "GitHunt: /opt/GitHunt/githunt.py" \
    || { [[ -f "$GITHUNT_DIR/githunt.py" ]] && ok "GitHunt: $GITHUNT_DIR/githunt.py" || warn "MISSING: GitHunt"; }
echo ""
echo "=== DONE ==="
