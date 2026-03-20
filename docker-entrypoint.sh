#!/bin/bash
# ==============================================================================
# Technieum Docker Entrypoint
# Handles initialization and startup of API, worker, or custom commands
# ==============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()  { echo -e "${GREEN}[+]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[-]${NC} $*"; }
log_section() { echo -e "\n${BLUE}[*] $*${NC}\n"; }

# ==============================================================================
# INITIALIZATION
# ==============================================================================

init_directories() {
    log_section "Initializing directories..."
    
    mkdir -p \
        "${TECHNIEUM_DATA}/scans" \
        "${TECHNIEUM_DATA}/output" \
        "${TECHNIEUM_DATA}/logs" \
        /var/run/technieum
    
    chmod 755 "${TECHNIEUM_DATA}" "${TECHNIEUM_DATA}"/*
    
    log_info "Directories ready"
}

init_database() {
    log_section "Initializing database..."
    
    if [[ -f "${TECHNIEUM_DB_PATH}" ]]; then
        log_info "Database already exists: ${TECHNIEUM_DB_PATH}"
    else
        log_info "Creating new database at: ${TECHNIEUM_DB_PATH}"
        
        # Run migrations
        cd "${TECHNIEUM_HOME}"
        python -c "
from app.db.database import DatabaseManager
db = DatabaseManager('${TECHNIEUM_DB_PATH}')
print('✓ Database initialized')
" || log_warn "Database initialization failed - may already exist"
    fi
}

init_environment() {
    log_section "Environment Configuration"
    
    echo "Home: ${TECHNIEUM_HOME}"
    echo "Data: ${TECHNIEUM_DATA}"
    echo "Database: ${TECHNIEUM_DB_PATH}"
    echo "Python: $(python --version)"
    echo "Go: $(go version 2>/dev/null || echo 'not installed')"
    echo "Subfinder: $(subfinder --version 2>/dev/null || echo 'not installed')"
    echo "Nuclei: $(nuclei --version 2>/dev/null || echo 'not installed')"
}

# ==============================================================================
# STARTUP FUNCTIONS
# ==============================================================================

start_server() {
    log_section "Starting API Server..."
    
    cd "${TECHNIEUM_HOME}"
    
    # Run database migrations first
    log_info "Running migrations..."
    python -c "
from app.db.migrations.runner import apply_migrations
apply_migrations()
print('✓ Migrations applied')
" || log_warn "Migration check completed"
    
    # Start FastAPI with Uvicorn
    log_info "Starting Uvicorn on 0.0.0.0:${API_PORT}"
    
    exec python -m uvicorn api.server:app \
        --host 0.0.0.0 \
        --port "${API_PORT}" \
        --workers "${API_WORKERS:-4}" \
        --loop uvloop \
        --http httptools \
        --access-log \
        --log-level info
}

start_worker() {
    log_section "Starting Background Worker..."
    
    cd "${TECHNIEUM_HOME}"
    
    log_info "Starting job worker..."
    
    exec python -m app.workers.worker
}

start_combined() {
    log_section "Starting Combined Mode (API + Worker)..."
    
    cd "${TECHNIEUM_HOME}"
    
    # Run migrations
    log_info "Running migrations..."
    python -c "
from app.db.migrations.runner import apply_migrations
apply_migrations()
print('✓ Migrations applied')
" || log_warn "Migration check completed"
    
    # Start both services
    log_info "Starting API on 0.0.0.0:${API_PORT}"
    log_info "Starting Worker (TECHNIEUM_WORKER=true)"
    
    # Use supervisor-like approach with background job
    python -m app.workers.worker &
    WORKER_PID=$!
    
    trap "kill $WORKER_PID 2>/dev/null || true" EXIT
    
    exec python -m uvicorn api.server:app \
        --host 0.0.0.0 \
        --port "${API_PORT}" \
        --workers "${API_WORKERS:-1}" \
        --loop uvloop \
        --http httptools \
        --access-log \
        --log-level info
}

run_scan() {
    log_section "Running Scan: $*"
    
    cd "${TECHNIEUM_HOME}"
    
    exec python technieum.py "$@"
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
  query <args>        Query results (e.g., query -t example.com --summary)
  shell               Start interactive bash shell
  help                Show this help message

Environment Variables:
  TECHNIEUM_ENV              Environment: development, production (default: production)
  TECHNIEUM_WORKER           Enable worker: true/false (default: true)
  API_HOST                   API listen address (default: 0.0.0.0)
  API_PORT                   API port (default: 8000)
  API_WORKERS                Number of worker threads (default: 4)
  
Examples:
  docker run -p 8000:8000 technieum:latest server
  docker run technieum:latest scan example.com
  docker run -it technieum:latest shell
  docker run -it technieum:latest query -t example.com --summary

EOF
}

# ==============================================================================
# MAIN ENTRYPOINT
# ==============================================================================

main() {
    # Initialize
    init_directories
    init_database
    init_environment
    
    # Get command (default: combined)
    COMMAND="${1:-combined}"
    shift || true
    
    case "$COMMAND" in
        server)
            start_server
            ;;
        worker)
            start_worker
            ;;
        combined)
            start_combined
            ;;
        scan)
            run_scan "$@"
            ;;
        query)
            run_query "$@"
            ;;
        shell)
            log_info "Starting interactive shell..."
            exec bash
            ;;
        help|--help|-h)
            show_help
            exit 0
            ;;
        *)
            # Allow arbitrary commands
            log_info "Running command: $COMMAND $*"
            exec "$COMMAND" "$@"
            ;;
    esac
}

# Run main function
main "$@"
