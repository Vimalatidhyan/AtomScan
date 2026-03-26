#!/bin/bash
# ==============================================================================
# Technieum Docker Entrypoint
# Handles initialization and startup of API, worker, or custom commands
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

API_PORT="${API_PORT:-8000}"
TECHNIEUM_HOME="${TECHNIEUM_HOME:-/opt/technieum}"
TECHNIEUM_DATA="${TECHNIEUM_DATA:-/opt/technieum/data}"
TECHNIEUM_DB_PATH="${TECHNIEUM_DB_PATH:-${TECHNIEUM_DATA}/technieum.db}"
VIRTUAL_ENV="${VIRTUAL_ENV:-/opt/venv}"

log_info()    { echo -e "${GREEN}[+]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
log_error()   { echo -e "${RED}[-]${NC} $*"; }
log_section() { echo -e "\n${BLUE}[*] $*${NC}\n"; }

# ==============================================================================
# Activate virtual environment
# ==============================================================================
activate_venv() {
    if [ -f "${VIRTUAL_ENV}/bin/activate" ]; then
        # shellcheck disable=SC1091
        . "${VIRTUAL_ENV}/bin/activate"
        log_info "Python venv active: ${VIRTUAL_ENV}"
    else
        log_warn "No venv at ${VIRTUAL_ENV} — using system Python"
    fi
}

# ==============================================================================
# INITIALIZATION
# ==============================================================================

init_directories() {
    log_section "Initializing directories"

    mkdir -p \
        "${TECHNIEUM_DATA}/scans" \
        "${TECHNIEUM_DATA}/output" \
        "${TECHNIEUM_DATA}/logs" \
        /var/run/technieum

    chmod 755 "${TECHNIEUM_DATA}" 2>/dev/null || true

    log_info "Directories ready"
}

init_database() {
    log_section "Initializing database"

    if [ -f "${TECHNIEUM_DB_PATH}" ]; then
        log_info "Database exists: ${TECHNIEUM_DB_PATH}"
    else
        log_info "Creating database: ${TECHNIEUM_DB_PATH}"
        cd "${TECHNIEUM_HOME}"
        python -c "
from app.db.database import apply_migrations
apply_migrations()
print('Database initialized')
" 2>&1 || log_warn "Database init returned non-zero (may already exist)"
    fi
}

init_environment() {
    log_section "Environment Configuration"

    echo "  Home:      ${TECHNIEUM_HOME}"
    echo "  Data:      ${TECHNIEUM_DATA}"
    echo "  Database:  ${TECHNIEUM_DB_PATH}"
    echo "  Python:    $(python --version 2>&1 || echo 'not found')"
    echo "  Subfinder: $(subfinder -version 2>/dev/null || echo 'not installed')"
    echo "  Nuclei:    $(nuclei -version 2>/dev/null  || echo 'not installed')"
    echo "  Nmap:      $(nmap --version 2>/dev/null | head -1 || echo 'not installed')"
}

# ==============================================================================
# STARTUP FUNCTIONS
# ==============================================================================

start_server() {
    log_section "Starting API Server on 0.0.0.0:${API_PORT}"

    cd "${TECHNIEUM_HOME}"

    log_info "Running migrations..."
    python -c "
from app.db.database import apply_migrations
apply_migrations()
print('Migrations applied')
" 2>&1 || log_warn "Migration step returned non-zero"

    export TECHNIEUM_WORKER="${TECHNIEUM_WORKER:-true}"

    exec python -m uvicorn app.api.server:app \
        --host 0.0.0.0 \
        --port "${API_PORT}" \
        --workers "${API_WORKERS:-1}" \
        --access-log \
        --log-level info
}

start_worker() {
    log_section "Starting Background Worker"

    cd "${TECHNIEUM_HOME}"
    exec python -m app.workers.worker
}

start_combined() {
    log_section "Starting Combined Mode (API + Worker)"

    cd "${TECHNIEUM_HOME}"

    log_info "Running migrations..."
    python -c "
from app.db.database import apply_migrations
apply_migrations()
print('Migrations applied')
" 2>&1 || log_warn "Migration step returned non-zero"

    log_info "Starting dedicated worker process"
    python -m app.workers.worker &
    WORKER_PID=$!
    trap "kill ${WORKER_PID} 2>/dev/null || true" EXIT

    log_info "Starting API on 0.0.0.0:${API_PORT}"
    export TECHNIEUM_WORKER=false
    exec python -m uvicorn app.api.server:app \
        --host 0.0.0.0 \
        --port "${API_PORT}" \
        --workers "${API_WORKERS:-1}" \
        --access-log \
        --log-level info
}

run_scan() {
    log_section "Running Scan: $*"

    cd "${TECHNIEUM_HOME}"
    export TECHNIEUM_OUTPUT_DIR="${TECHNIEUM_OUTPUT_DIR:-${TECHNIEUM_DATA}/output}"
    mkdir -p "${TECHNIEUM_OUTPUT_DIR}" "${TECHNIEUM_LOGS_DIR:-${TECHNIEUM_DATA}/logs}"
    log_info "Output dir: ${TECHNIEUM_OUTPUT_DIR}"

    exec python technieum.py "$@"
}

run_oneshot() {
    local target="${1:-}"
    if [ -z "${target}" ]; then
        log_error "oneshot requires a target domain"
        exit 2
    fi
    log_section "Automated scan: ${target}"
    cd "${TECHNIEUM_HOME}"
    export TECHNIEUM_OUTPUT_DIR="${TECHNIEUM_OUTPUT_DIR:-${TECHNIEUM_DATA}/output}"
    mkdir -p "${TECHNIEUM_OUTPUT_DIR}" "${TECHNIEUM_LOGS_DIR:-${TECHNIEUM_DATA}/logs}"
    exec python technieum.py -t "${target}" --phases 0,1,2,3,4,5,6,7,8,9
}

run_query() {
    log_section "Running Query: $*"
    cd "${TECHNIEUM_HOME}"
    exec python query.py "$@"
}

show_help() {
    cat << 'EOF'
Technieum Docker Entrypoint

Usage: technieum <command> [args...]

Commands:
  server              Start API server only
  worker              Start background worker only
  combined            Start API server + worker (default)
  scan <target>       Run a scan (e.g., scan example.com)
  oneshot <target>    Full automated scan (all phases)
  query <args>        Query results (e.g., query -t example.com --summary)
  shell               Start interactive bash shell
  help                Show this help message

Environment Variables:
  TECHNIEUM_ENV              development | production (default: production)
  TECHNIEUM_WORKER           Enable embedded worker: true/false
  API_HOST                   API listen address (default: 0.0.0.0)
  API_PORT                   API port (default: 8000)
  API_WORKERS                Uvicorn worker processes (default: 1)

Examples:
  docker run -p 8000:8000 technieum:latest combined
  docker run technieum:latest scan example.com
  docker run -it technieum:latest shell
  docker run -it technieum:latest query -t example.com --summary

EOF
}

# ==============================================================================
# MAIN
# ==============================================================================

main() {
    activate_venv
    init_directories
    init_database
    init_environment

    COMMAND="${1:-combined}"
    shift || true

    case "${COMMAND}" in
        server)   start_server   ;;
        worker)   start_worker   ;;
        combined) start_combined ;;
        scan)     run_scan "$@"  ;;
        oneshot)  run_oneshot "$@" ;;
        query)    run_query "$@" ;;
        shell)
            log_info "Starting interactive shell..."
            exec bash
            ;;
        help|--help|-h)
            show_help
            exit 0
            ;;
        *)
            log_info "Running command: ${COMMAND} $*"
            exec "${COMMAND}" "$@"
            ;;
    esac
}

main "$@"
