FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/root/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    TECHNIEUM_OUTPUT_DIR=/opt/technieum/output \
    TECHNIEUM_DB_PATH=/opt/technieum/technieum.db \
    TECHNIEUM_NMAP_HOST_TIMEOUT=240 \
    TECHNIEUM_NMAP_MAX_HOSTS=80 \
    TECHNIEUM_NMAP_FULL=0 \
    LOG_LEVEL=INFO

WORKDIR /opt/technieum

# Base runtime/build dependencies used by install_tools.sh and app startup.
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    wget \
    git \
    jq \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    golang-go \
    npm \
    ruby-full \
    procps \
    net-tools \
    iproute2 \
    lsof \
    tmux \
    screen \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Ensure scripts are executable, then install full scanning toolchain.
RUN chmod +x ./install_tools.sh ./start.sh ./lib/run_scan.sh ./modules/*.sh ./scripts/*.sh || true
RUN ./install_tools.sh
# Extra safety in container builds: ensure key binaries exist even when apt mirrors are flaky.
RUN bash -lc "if ! command -v whois >/dev/null 2>&1; then apt-get update && apt-get install -y --no-install-recommends whois || true; fi"
RUN bash -lc "command -v rustscan >/dev/null 2>&1 || cargo install rustscan || true"

EXPOSE 8000

VOLUME ["/opt/technieum/output", "/opt/technieum/logs"]

CMD ["bash", "-lc", "./start.sh --port ${PORT:-8000}"]
