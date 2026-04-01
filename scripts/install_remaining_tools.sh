#!/usr/bin/env bash
# Install remaining missing Technieum tools
set -e
export GOPATH=/home/Vimalatithyan/go
export PATH=/usr/lib/go-1.24/bin:/home/Vimalatithyan/go/bin:$PATH
LOG=/tmp/technieum_tool_install.log

go_install() {
    local pkg="$1" bin="$2"
    if command -v "$bin" &>/dev/null; then
        echo "[OK] $bin already installed"
        return
    fi
    echo "[~] Installing $bin..."
    go install "$pkg" 2>&1 && echo "[OK] $bin installed" || echo "[WARN] $bin failed"
}

go_install "github.com/hakluke/hakrawler@latest"              "hakrawler"
go_install "github.com/haccer/subjack@latest"                 "subjack"
go_install "github.com/Ice3man543/SubOver@latest"             "SubOver"
go_install "github.com/gitleaks/gitleaks/v8@latest"           "gitleaks"
go_install "github.com/jaeles-project/gospider@latest"        "gospider"
go_install "github.com/trufflesecurity/trufflehog/v3@latest"  "trufflehog"
go_install "github.com/Brosck/mantra@latest"                  "mantra"
go_install "github.com/edoardottt/cariddi/cmd/cariddi@latest" "cariddi"

echo ""
echo "=== git-secrets ==="
if command -v git-secrets &>/dev/null; then
    echo "[OK] git-secrets already installed"
else
    TMPDIR=$(mktemp -d)
    git clone --depth 1 https://github.com/awslabs/git-secrets.git "$TMPDIR/git-secrets" 2>&1
    cd "$TMPDIR/git-secrets"
    make install PREFIX=/usr/local 2>&1 && echo "[OK] git-secrets installed" || echo "[WARN] git-secrets install failed (may need sudo)"
    cd - >/dev/null
    rm -rf "$TMPDIR"
fi

echo ""
echo "=== GitHunt ==="
if [[ -f /opt/GitHunt/githunt.py ]]; then
    echo "[OK] GitHunt already present"
else
    git clone --depth 1 https://github.com/HightechSec/git-scanner.git /opt/GitHunt 2>&1 \
        && echo "[OK] GitHunt cloned to /opt/GitHunt" \
        || echo "[WARN] GitHunt clone failed (optional)"
fi

echo ""
echo "=== Final tool check ==="
for t in gau waybackurls hakrawler subjack SubOver gitleaks gospider trufflehog git-secrets; do
    command -v "$t" &>/dev/null && echo "[OK] $t: $(command -v $t)" || echo "[MISS] $t"
done
[[ -f /opt/GitHunt/githunt.py ]] && echo "[OK] GitHunt: /opt/GitHunt/githunt.py" || echo "[MISS] GitHunt"
echo ""
echo "=== DONE ==="
