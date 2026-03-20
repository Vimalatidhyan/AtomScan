# ==============================================================================
# Technieum — Multi-Stage Docker Build
# Best Practices: Multi-stage, minimal base, security-focused, layer caching
# ==============================================================================

FROM ubuntu:22.04 AS base

LABEL maintainer="Technieum Team" \
      description="Technieum - Attack Surface Management Framework" \
      version="1.0"

ENV DEBIAN_FRONTEND=noninteractive \
    TECHNIEUM_HOME=/opt/technieum \
    TECHNIEUM_DATA=/data \
    TECHNIEUM_WORKER=true \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# Install base system tools and scanning dependencies
# Clean apt lists in same layer to reduce image size
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    # System essentials
    curl wget git build-essential ca-certificates software-properties-common \
    # Shell scripting
    bash zsh sudo \
    # Network tools
    whois dnsmasq nmap netcat-openbsd \
    dnsutils bind9-utils iputils-ping traceroute \
    # Programming languages
    python3.11 python3-pip python3-venv golang-go ruby \
    # Development headers
    libssl-dev libffi-dev libxml2-dev libxslt1-dev \
    # Command-line utilities
    jq xmlstarlet unzip zip tar gzip bzip2 xz-utils \
    # Additional tools
    git-all openssh-client \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Ensure Python 3.11 is default
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.11 1 && \
    update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1 && \
    update-alternatives --install /usr/bin/pip pip /usr/bin/pip3 1 && \
    python --version

# Create application directories
RUN mkdir -p ${TECHNIEUM_HOME} ${TECHNIEUM_DATA} /opt/technieum-tools /opt/wordlists && \
    chmod 755 ${TECHNIEUM_HOME} ${TECHNIEUM_DATA}

FROM base AS builder

ENV GOPATH=/root/go \
    GO111MODULE=on \
    GOPROXY=https://proxy.golang.org,direct

RUN go version

# Install Go tools with BuildKit cache mounts for go modules
RUN --mount=type=cache,target=/root/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/go/bin,sharing=locked \
    mkdir -p /root/go/bin && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/ffuf/ffuf@latest && \
    go install -v github.com/tomnomnom/gau@latest; \
    cp -r /root/go/bin/* /usr/local/bin/ 2>/dev/null || true

FROM builder AS python-deps

WORKDIR ${TECHNIEUM_HOME}

COPY requirements.txt requirements-api.txt ./

# Install Python packages with BuildKit cache mount
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt && \
    pip install -r requirements-api.txt && \
    python -c "import fastapi, sqlalchemy, pydantic; print('✓ Core packages OK')"

FROM python-deps AS runtime

WORKDIR ${TECHNIEUM_HOME}

# Create runtime directories first (layer caching optimization)
RUN mkdir -p \
    ${TECHNIEUM_DATA}/scans \
    ${TECHNIEUM_DATA}/output \
    ${TECHNIEUM_DATA}/logs \
    /var/run/technieum && \
    chmod 755 ${TECHNIEUM_DATA} ${TECHNIEUM_DATA}/* /var/run/technieum

# Copy application code
COPY --chown=root:root . .

# Make scripts executable
RUN chmod +x scripts/*.sh 2>/dev/null || true && \
    chmod +x docker-entrypoint.sh install.sh setup.sh start.sh 2>/dev/null || true

# Set up environment
ENV TECHNIEUM_DB_PATH=${TECHNIEUM_DATA}/technieum.db \
    TECHNIEUM_OUTPUT_DIR=${TECHNIEUM_DATA}/output \
    TECHNIEUM_LOGS_DIR=${TECHNIEUM_DATA}/logs

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:${API_PORT:-8000}/api/v1/health || exit 1

# Expose ports
EXPOSE 8000 8001 9000

ENV PYTHONPATH=${TECHNIEUM_HOME}

CMD ["uvicorn", "app.api.server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]

# Default entrypoint
ENTRYPOINT ["/opt/technieum/docker-entrypoint.sh"]
CMD ["server"]
