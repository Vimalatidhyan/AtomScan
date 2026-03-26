# ==============================================================================
# Technieum — Multi-Stage Docker Build
# Target Base: kalilinux/kali-rolling (Full scan tools & pipelines)
# ==============================================================================

FROM kalilinux/kali-rolling AS base

LABEL maintainer="Technieum Team" \
      description="Technieum - Attack Surface Management Framework" \
      version="2.2"

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
    GOPROXY=https://proxy.golang.org,direct

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
    dnsutils bind9-dnsutils bind9-host whois dnsmasq iputils-ping \
    traceroute netcat-openbsd \
    nmap masscan rustscan nikto sqlmap wapiti wpscan skipfish \
    testssl.sh sslyze dirsearch feroxbuster \
    gnupg apt-transport-https \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Ensure python/pip aliases exist
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 1 && \
    update-alternatives --install /usr/bin/pip pip /usr/bin/pip3 1

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
    rm -f /tmp/go.tar.gz

# Install Go recon tools
# Includes all Phase 1-4 ProjectDiscovery tools + others
RUN --mount=type=cache,target=/root/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/go/bin,sharing=locked \
    mkdir -p /root/go/bin && \
    export PATH=$PATH:/usr/local/go/bin && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest && \
    go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/hakluke/hakrawler@latest && \
    go install -v github.com/haccer/subjack@latest && \
    go install -v github.com/jaeles-project/gospider@latest && \
    go install -v github.com/hahwul/dalfox/v2@latest && \
    go install -v github.com/edoardottt/cariddi/cmd/cariddi@latest && \
    go install -v github.com/Brosck/mantra@latest && \
    go install -v github.com/0xSojalSec/Subprober@latest && \
    go install -v github.com/mrhenrike/dnsprober@latest && \
    go install -v github.com/sensepost/gowitness@latest && \
    go install -v github.com/gitleaks/gitleaks/v8@latest && \
    go install -v github.com/trufflesecurity/trufflehog/v3@latest && \
    cp -r /root/go/bin/* /usr/local/bin/ 2>/dev/null || true

# ==============================================================================
# PHASE 2B: Python Dependencies
# ==============================================================================
FROM base AS python-deps

WORKDIR ${TECHNIEUM_HOME}
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

COPY requirements.txt requirements-api.txt ./

# We use venv with --break-system-packages tools seamlessly inside Docker
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    python3 -m venv "${VIRTUAL_ENV}" && \
    "${VIRTUAL_ENV}/bin/pip" install --upgrade pip setuptools wheel && \
    "${VIRTUAL_ENV}/bin/pip" install -r requirements.txt && \
    "${VIRTUAL_ENV}/bin/pip" install -r requirements-api.txt && \
    "${VIRTUAL_ENV}/bin/pip" install arjun dirsearch sslyze censys shodan || true

FROM python-deps AS runtime

ENV VIRTUAL_ENV=/opt/venv \
    PATH="${VIRTUAL_ENV}/bin:${PATH}"

WORKDIR ${TECHNIEUM_HOME}
RUN mkdir -p \
    ${TECHNIEUM_DATA}/scans \
    ${TECHNIEUM_DATA}/output \
    ${TECHNIEUM_DATA}/logs \
    /var/run/technieum && \
    chmod 755 ${TECHNIEUM_DATA} ${TECHNIEUM_DATA}/* /var/run/technieum

# Copy compiled Go tools from builder
COPY --from=builder /usr/local/bin/ /usr/local/bin/

# Copy application code
COPY --chown=root:root . .

# Make scripts executable
RUN chmod +x scripts/*.sh 2>/dev/null || true && \
    chmod +x docker-entrypoint.sh install.sh setup.sh start.sh 2>/dev/null || true

# ==============================================================================
# PHASE 3: Install Additional Tools (Git clones, gems, npm)
# ==============================================================================

# LinkFinder
RUN if [ ! -d /opt/LinkFinder ]; then \
        git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git /opt/LinkFinder; \
    fi

# SecretFinder
RUN if [ ! -d /opt/SecretFinder ]; then \
        git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git /opt/SecretFinder; \
    fi

# git-secrets
RUN if ! command -v git-secrets &>/dev/null; then \
        TMPDIR=$(mktemp -d) && \
        git clone --depth 1 https://github.com/awslabs/git-secrets.git "$TMPDIR/git-secrets" && \
        cd "$TMPDIR/git-secrets" && make install PREFIX=/usr/local && \
        cd - >/dev/null && rm -rf "$TMPDIR"; \
    fi

# npm tools (newman, retire.js)
RUN if command -v npm &>/dev/null; then \
        npm install -g newman retire 2>/dev/null || true; \
    fi

# Nuclei templates - force download into root tools directory and standard config
RUN nuclei -update-templates -silent 2>/dev/null || true
RUN mkdir -p /root/tools/nuclei-templates && \
    cp -R /root/.local/nuclei-templates/* /root/tools/nuclei-templates/ 2>/dev/null || true

# ==============================================================================
# PHASE 4: Environment & Entrypoint Configuration
# ==============================================================================

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
