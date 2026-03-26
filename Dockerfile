# ==============================================================================
# Technieum — Multi-Stage Docker Build with Tool Verification
# Best Practices: Multi-stage, minimal base, security-focused, layer caching
# ==============================================================================

FROM kalilinux/kali-rolling AS base

LABEL maintainer="Technieum Team" \
      description="Technieum - Attack Surface Management Framework (Kali)" \
      version="2.1"

ENV DEBIAN_FRONTEND=noninteractive \
    TECHNIEUM_HOME=/opt/technieum \
    TECHNIEUM_DATA=/data \
    TECHNIEUM_WORKER=true \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/usr/local/go/bin:/root/go/bin:${PATH}" \
    API_PORT=8000 \
    GOPATH=/root/go \
    GO111MODULE=on \
    GOPROXY=https://proxy.golang.org,direct \
    GITHUB_TOKEN="" \
    PDCP_API_KEY="c4a746d8-4054-4f3f-b8e7-dea203735579"

# ==============================================================================
# PHASE 1: System Packages (apt)
# ==============================================================================
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    curl wget git jq unzip zip tar gzip bzip2 xz-utils bash zsh sudo \
    openssh-client ca-certificates build-essential pkg-config \
    python3 python3-pip python3-venv python3-dev python3-setuptools python3-wheel \
    ruby ruby-dev \
    nodejs npm default-jre \
    libssl-dev libffi-dev libxml2-dev libxslt1-dev libpcap-dev \
    dnsutils bind9-dnsutils whois dnsmasq iputils-ping traceroute netcat-openbsd \
    nmap masscan nikto sqlmap wapiti wpscan testssl.sh sslyze \
    gnupg apt-transport-https \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Ensure python/pip aliases exist
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 1 && \
    update-alternatives --install /usr/bin/pip pip /usr/bin/pip3 1 && \
    python --version

# Create application directories
RUN mkdir -p ${TECHNIEUM_HOME} ${TECHNIEUM_DATA} /opt/technieum-tools /opt/wordlists && \
    chmod 755 ${TECHNIEUM_HOME} ${TECHNIEUM_DATA}

FROM base AS builder

# ==============================================================================
# PHASE 2: Install Go and Go-based tools
# ==============================================================================
RUN ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64)  GO_ARCH="amd64" ;; \
        aarch64) GO_ARCH="arm64" ;; \
        *)       GO_ARCH="amd64" ;; \
    esac; \
    wget -q "https://go.dev/dl/go1.22.4.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tar.gz && \
    rm -rf /usr/local/go && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm -f /tmp/go.tar.gz && \
    go version

# Install Go recon tools
RUN --mount=type=cache,target=/root/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/go/bin,sharing=locked \
    mkdir -p /root/go/bin && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest && \
    go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest && \
    go install -v github.com/bee-san/RustScan@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/ffuf/ffuf@latest && \
    go install -v github.com/tomnomnom/gau@latest && \
    go install -v github.com/hakluke/hakrawler@latest && \
    go install -v github.com/haccer/subjack@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/jaeles-project/gospider@latest && \
    go install -v github.com/hahwul/dalfox/v2@latest && \
    go install -v github.com/edoardottt/cariddi/cmd/cariddi@latest && \
    go install -v github.com/Brosck/mantra@latest && \
    go install -v github.com/0xSojalSec/Subprober@latest && \
    go install -v github.com/mrhenrike/dnsprober@latest; \
    cp -r /root/go/bin/* /usr/local/bin/ 2>/dev/null || true

# ==============================================================================
# PHASE 2B: Python Dependencies
# ==============================================================================
FROM base AS python-deps

ARG GITHUB_TOKEN=""
ARG PDCP_API_KEY="c4a746d8-4054-4f3f-b8e7-dea203735579"

ENV GITHUB_TOKEN=${GITHUB_TOKEN} \
    PDCP_API_KEY=${PDCP_API_KEY}

WORKDIR ${TECHNIEUM_HOME}
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

COPY requirements.txt requirements-api.txt ./

RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    python3 -m venv "${VIRTUAL_ENV}" && \
    "${VIRTUAL_ENV}/bin/pip" install --upgrade pip setuptools wheel && \
    "${VIRTUAL_ENV}/bin/pip" install -r requirements.txt && \
    "${VIRTUAL_ENV}/bin/pip" install -r requirements-api.txt && \
    "${VIRTUAL_ENV}/bin/pip" install trufflehog gitleaks==8.24.2 || true && \
    "${VIRTUAL_ENV}/bin/python" -c "import fastapi, sqlalchemy, pydantic; print('Core packages OK')"

FROM python-deps AS runtime

ARG GITHUB_TOKEN=""
ARG PDCP_API_KEY="c4a746d8-4054-4f3f-b8e7-dea203735579"
ARG INSTALL_SECLISTS=false
ARG INSTALL_FULL_TOOLSET=true

ENV GITHUB_TOKEN=${GITHUB_TOKEN} \
    PDCP_API_KEY=${PDCP_API_KEY} \
    VIRTUAL_ENV=/opt/venv \
    PATH="${VIRTUAL_ENV}/bin:${PATH}"

WORKDIR ${TECHNIEUM_HOME}
RUN mkdir -p \
    ${TECHNIEUM_DATA}/scans \
    ${TECHNIEUM_DATA}/output \
    ${TECHNIEUM_DATA}/logs \
    /var/run/technieum && \
    chmod 755 ${TECHNIEUM_DATA} ${TECHNIEUM_DATA}/* /var/run/technieum

# Optional heavy wordlist install
RUN if [ "${INSTALL_SECLISTS}" = "true" ]; then \
      mkdir -p /usr/share/seclists && \
      git clone --depth=1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists; \
    else \
      mkdir -p /usr/share/seclists; \
    fi

# Copy application code
COPY --chown=root:root . .

# Make scripts executable
RUN chmod +x scripts/*.sh 2>/dev/null || true && \
    chmod +x docker-entrypoint.sh install.sh setup.sh start.sh 2>/dev/null || true

# ==============================================================================
# PHASE 3: Install Additional Tools (Git clones, gems, npm)
# ==============================================================================
# testssl.sh
RUN if [ ! -f /usr/local/bin/testssl.sh ]; then \
        mkdir -p /opt/technieum-tools && \
        git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/technieum-tools/testssl.sh && \
        ln -sf /opt/technieum-tools/testssl.sh/testssl.sh /usr/local/bin/testssl.sh; \
    fi

# LinkFinder
RUN if [ ! -d /opt/LinkFinder ]; then \
        git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git /opt/LinkFinder; \
    fi

# SecretFinder
RUN if [ ! -d /opt/SecretFinder ]; then \
        git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git /opt/SecretFinder; \
    fi

# GitHunt
RUN if [ ! -d /opt/GitHunt ]; then \
        git clone --depth 1 https://github.com/HightechSec/git-scanner.git /opt/GitHunt; \
    fi

# git-secrets
RUN if ! command -v git-secrets &>/dev/null; then \
        TMPDIR=$(mktemp -d) && \
        git clone --depth 1 https://github.com/awslabs/git-secrets.git "$TMPDIR/git-secrets" && \
        cd "$TMPDIR/git-secrets" && make install PREFIX=/usr/local && \
        cd - >/dev/null && rm -rf "$TMPDIR"; \
    fi

# wpscan (Ruby gem)
RUN if ! command -v wpscan &>/dev/null; then \
        gem install wpscan || true; \
    fi

# npm tools (newman, retire.js)
RUN if command -v npm &>/dev/null; then \
        npm install -g newman retire 2>/dev/null || true; \
    fi

# Nuclei templates
RUN nuclei -update-templates -silent 2>/dev/null || true

# ==============================================================================
# PHASE 4: Tool Verification & Auto-Fix
# ==============================================================================
RUN KALI_PACKAGES="nmap masscan nikto sqlmap wapiti wpscan testssl.sh sslyze" && \
    for pkg in $KALI_PACKAGES; do \
        if ! command -v "$pkg" &>/dev/null && ! [ -f "/usr/bin/$pkg" ] && ! [ -f "/usr/local/bin/$pkg" ]; then \
            echo "[VERIFY] $pkg not found - attempting reinstall..."; \
            apt-get update && apt-get install -y "$pkg" 2>/dev/null || echo "[VERIFY] $pkg install failed"; \
        fi; \
    done

RUN GO_TOOLS="subfinder amass assetfinder dnsx httpx asnmap mapcidr nuclei katana ffuf gau waybackurls hakrawler subjack gospider dalfox cariddi mantra gitleaks trufflehog" && \
    for tool in $GO_TOOLS; do \
        if ! command -v "$tool" &>/dev/null; then \
            echo "[VERIFY] $tool not found - attempting reinstall via Go..."; \
            case "$tool" in \
                subfinder) go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest ;; \
                amass) go install github.com/owasp-amass/amass/v4/...@master ;; \
                assetfinder) go install github.com/tomnomnom/assetfinder@latest ;; \
                dnsx) go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest ;; \
                httpx) go install github.com/projectdiscovery/httpx/cmd/httpx@latest ;; \
                asnmap) go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest ;; \
                mapcidr) go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest ;; \
                nuclei) go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest ;; \
                katana) go install github.com/projectdiscovery/katana/cmd/katana@latest ;; \
                ffuf) go install github.com/ffuf/ffuf/v2@latest ;; \
                gau) go install github.com/lc/gau/v2/cmd/gau@latest ;; \
                waybackurls) go install github.com/tomnomnom/waybackurls@latest ;; \
                hakrawler) go install github.com/hakluke/hakrawler@latest ;; \
                subjack) go install github.com/haccer/subjack@latest ;; \
                gospider) go install github.com/jaeles-project/gospider@latest ;; \
                dalfox) go install github.com/hahwul/dalfox/v2@latest ;; \
                cariddi) go install github.com/edoardottt/cariddi/cmd/cariddi@latest ;; \
                mantra) go install github.com/Brosck/mantra@latest ;; \
                gitleaks) go install github.com/gitleaks/gitleaks/v8@latest ;; \
                trufflehog) go install github.com/trufflesecurity/trufflehog/v3@latest ;; \
            esac || echo "[VERIFY] $tool failed"; \
        fi; \
    done

RUN echo "========================================" && \
    echo "TOOL VERIFICATION REPORT" && \
    echo "========================================" && \
    for cmd in nmap masscan nikto sqlmap wapiti wpscan testssl.sh sslyze subfinder amass assetfinder dnsx httpx asnmap mapcidr nuclei katana ffuf gau waybackurls hakrawler subjack gospider dalfox cariddi mantra gitleaks trufflehog git-secrets; do \
        if command -v "$cmd" &>/dev/null; then \
            echo "[OK]   $cmd"; \
        else \
            echo "[FAIL] $cmd - NOT FOUND"; \
        fi; \
    done && \
    echo "========================================"

# Set up environment
ENV TECHNIEUM_DB_PATH=${TECHNIEUM_DATA}/technieum.db \
    TECHNIEUM_OUTPUT_DIR=${TECHNIEUM_DATA}/output \
    TECHNIEUM_LOGS_DIR=${TECHNIEUM_DATA}/logs \
    TECHNIEUM_NMAP_TIMEOUT=7200 \
    TECHNIEUM_NMAP_HOST_TIMEOUT=180 \
    TECHNIEUM_NMAP_MAX_HOSTS=50 \
    PYTHONPATH=${TECHNIEUM_HOME}

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=5 \
    CMD curl -sf http://localhost:${API_PORT:-8000}/health || exit 1

EXPOSE 8000

ENTRYPOINT ["/opt/technieum/docker-entrypoint.sh"]
CMD ["server"]
