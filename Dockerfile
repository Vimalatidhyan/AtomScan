# ==============================================================================
# Technieum — Dockerfile
# Base: kalilinux/kali-rolling (security tools + scan pipeline)
# Build: 2-stage (Go tool compilation → final runtime)
# ==============================================================================

# ==============================================================================
# STAGE 1 — Compile Go-based security tools
# ==============================================================================
FROM kalilinux/kali-rolling AS go-builder

ENV DEBIAN_FRONTEND=noninteractive \
    GOPATH=/root/go \
    GO111MODULE=on \
    GOPROXY=https://proxy.golang.org,direct

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        wget ca-certificates git gcc g++ libc6-dev make \
        libpcap-dev pkg-config && \
    rm -rf /var/lib/apt/lists/*

RUN ARCH="$(dpkg --print-architecture)" && \
    wget -q "https://go.dev/dl/go1.22.5.linux-${ARCH}.tar.gz" -O /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm -f /tmp/go.tar.gz

ENV PATH="/usr/local/go/bin:${GOPATH}/bin:${PATH}"

RUN mkdir -p /go-tools

# ProjectDiscovery suite — core reconnaissance tools
RUN for spec in \
      "subfinder  github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" \
      "httpx      github.com/projectdiscovery/httpx/cmd/httpx@latest" \
      "dnsx       github.com/projectdiscovery/dnsx/cmd/dnsx@latest" \
      "nuclei     github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" \
      "asnmap     github.com/projectdiscovery/asnmap/cmd/asnmap@latest" \
      "mapcidr    github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest" \
      "katana     github.com/projectdiscovery/katana/cmd/katana@latest" \
    ; do \
      name=$(echo $spec | awk '{print $1}'); \
      pkg=$(echo $spec  | awk '{print $2}'); \
      echo "==> Installing ${name} ..."; \
      go install -v "${pkg}" 2>&1 \
        && echo "[OK]   ${name}" \
        || echo "[SKIP] ${name}"; \
    done; \
    cp -r ${GOPATH}/bin/* /go-tools/ 2>/dev/null; true

# Community recon / fuzzing / crawling tools
RUN for spec in \
      "assetfinder  github.com/tomnomnom/assetfinder@latest" \
      "waybackurls  github.com/tomnomnom/waybackurls@latest" \
      "ffuf         github.com/ffuf/ffuf/v2@latest" \
      "gau          github.com/lc/gau/v2/cmd/gau@latest" \
      "hakrawler    github.com/hakluke/hakrawler@latest" \
      "subjack      github.com/haccer/subjack@latest" \
      "gospider     github.com/jaeles-project/gospider@latest" \
      "dalfox       github.com/hahwul/dalfox/v2@latest" \
      "cariddi      github.com/edoardottt/cariddi/cmd/cariddi@latest" \
      "gitleaks     github.com/gitleaks/gitleaks/v8@latest" \
    ; do \
      name=$(echo $spec | awk '{print $1}'); \
      pkg=$(echo $spec  | awk '{print $2}'); \
      echo "==> Installing ${name} ..."; \
      go install -v "${pkg}" 2>&1 \
        && echo "[OK]   ${name}" \
        || echo "[SKIP] ${name}"; \
    done; \
    cp -r ${GOPATH}/bin/* /go-tools/ 2>/dev/null; true

# Optional / heavy tools — failures are completely non-fatal
RUN for spec in \
      "gowitness   github.com/sensepost/gowitness@latest" \
      "mantra      github.com/Brosck/mantra@latest" \
      "trufflehog  github.com/trufflesecurity/trufflehog/v3@latest" \
    ; do \
      name=$(echo $spec | awk '{print $1}'); \
      pkg=$(echo $spec  | awk '{print $2}'); \
      echo "==> Installing ${name} (optional) ..."; \
      go install -v "${pkg}" 2>&1 \
        && echo "[OK]   ${name}" \
        || echo "[SKIP] ${name} — non-critical"; \
    done; \
    cp -r ${GOPATH}/bin/* /go-tools/ 2>/dev/null; true

RUN echo "=== Compiled Go tools ===" && ls -1 /go-tools/

# ==============================================================================
# STAGE 2 — Final runtime image
# ==============================================================================
FROM kalilinux/kali-rolling AS runtime

LABEL maintainer="Technieum Team" \
      description="Technieum - Attack Surface Management Framework" \
      version="2.2"

ENV DEBIAN_FRONTEND=noninteractive \
    TECHNIEUM_HOME=/opt/technieum \
    TECHNIEUM_DATA=/opt/technieum/data \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VIRTUAL_ENV=/opt/venv \
    API_PORT=8000

ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

# ── System packages ──────────────────────────────────────────────────────────
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl wget git jq unzip bash sudo \
        openssh-client ca-certificates \
        python3 python3-pip python3-venv python3-dev \
        python3-setuptools python3-wheel \
        ruby ruby-dev \
        nodejs npm \
        build-essential pkg-config \
        libssl-dev libffi-dev libxml2-dev libxslt1-dev libpcap-dev \
        dnsutils bind9-dnsutils bind9-host whois \
        iputils-ping traceroute netcat-openbsd \
        nmap masscan nikto sqlmap wapiti wpscan skipfish \
        testssl.sh sslyze dirsearch feroxbuster \
        gnupg \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# ── Python / pip aliases ─────────────────────────────────────────────────────
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 1 2>/dev/null || true && \
    update-alternatives --install /usr/bin/pip    pip    /usr/bin/pip3    1 2>/dev/null || true

# ── Copy compiled Go tools from builder ──────────────────────────────────────
COPY --from=go-builder /go-tools/ /usr/local/bin/

# ── Create directory tree ────────────────────────────────────────────────────
RUN mkdir -p \
        ${TECHNIEUM_HOME} \
        ${TECHNIEUM_DATA}/scans \
        ${TECHNIEUM_DATA}/output \
        ${TECHNIEUM_DATA}/logs \
        /var/run/technieum \
        /opt/wordlists && \
    chmod 755 ${TECHNIEUM_HOME} ${TECHNIEUM_DATA}

WORKDIR ${TECHNIEUM_HOME}

# ── Python virtual-env & pip dependencies (cached unless requirements change)
COPY requirements.txt requirements-api.txt ./

RUN python3 -m venv "${VIRTUAL_ENV}" && \
    "${VIRTUAL_ENV}/bin/pip" install --no-cache-dir --upgrade pip setuptools wheel && \
    "${VIRTUAL_ENV}/bin/pip" install --no-cache-dir -r requirements.txt && \
    "${VIRTUAL_ENV}/bin/pip" install --no-cache-dir -r requirements-api.txt && \
    "${VIRTUAL_ENV}/bin/pip" install --no-cache-dir \
        arjun dirsearch sslyze censys shodan 2>/dev/null || true

# ── Copy application code ────────────────────────────────────────────────────
COPY . .

# ── Make scripts executable ──────────────────────────────────────────────────
RUN chmod +x docker-entrypoint.sh 2>/dev/null || true && \
    chmod +x scripts/*.sh          2>/dev/null || true && \
    chmod +x install.sh setup.sh start.sh 2>/dev/null || true

# ── Git-cloned tools ─────────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git /opt/LinkFinder 2>/dev/null || true
RUN git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git    /opt/SecretFinder 2>/dev/null || true

# ── git-secrets ──────────────────────────────────────────────────────────────
RUN cd /tmp && \
    git clone --depth 1 https://github.com/awslabs/git-secrets.git && \
    cd git-secrets && make install PREFIX=/usr/local && \
    cd / && rm -rf /tmp/git-secrets \
    || true

# ── npm tools ────────────────────────────────────────────────────────────────
RUN npm install -g newman retire 2>/dev/null || true

# ── Nuclei templates ─────────────────────────────────────────────────────────
RUN nuclei -update-templates -silent 2>/dev/null || true

# ── Runtime environment variables ────────────────────────────────────────────
ENV TECHNIEUM_DB_PATH=${TECHNIEUM_DATA}/technieum.db \
    TECHNIEUM_OUTPUT_DIR=${TECHNIEUM_DATA}/output \
    TECHNIEUM_LOGS_DIR=${TECHNIEUM_DATA}/logs \
    TECHNIEUM_NMAP_TIMEOUT=7200 \
    TECHNIEUM_NMAP_HOST_TIMEOUT=180 \
    TECHNIEUM_NMAP_MAX_HOSTS=50 \
    PYTHONPATH=${TECHNIEUM_HOME}

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=5 \
    CMD curl -sf http://localhost:${API_PORT:-8000}/health || exit 1

EXPOSE 8000

ENTRYPOINT ["/opt/technieum/docker-entrypoint.sh"]
CMD ["combined"]
