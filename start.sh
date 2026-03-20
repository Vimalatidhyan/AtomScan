#!/usr/bin/env bash
# Technieum Enterprise — single-command startup
#
# Usage:
#   ./start.sh [--port PORT] [--workers N]
#
# Starts the database migrations, the scan worker (background), and the
# API server (foreground). Kills the worker on Ctrl-C / SIGTERM.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Argument parsing ─────────────────────────────────────────────────────────
PORT=8000
WORKERS=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)    PORT="$2";    shift 2 ;;
        --workers) WORKERS="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--port PORT] [--workers N]"
            exit 0 ;;
        *)
            echo "Unknown argument: $1" >&2
            echo "Usage: $0 [--port PORT] [--workers N]" >&2
            exit 1 ;;
    esac
done

# ── Activate virtual environment ─────────────────────────────────────────────
if [[ -f ".venv/bin/activate" ]]; then
    # shellcheck source=/dev/null
    source ".venv/bin/activate"
    echo "[start] Virtual environment: .venv"
elif [[ -f "venv/bin/activate" ]]; then
    # shellcheck source=/dev/null
    source "venv/bin/activate"
    echo "[start] Virtual environment: venv"
else
    echo "[start] WARNING: No virtual environment found (venv/ or .venv/). Using system Python."
fi

# ── Banner ───────────────────────────────────────────────────────────────────
echo ""
echo "  ██████  ███████  ██████  ██████  ███    ██ ██   ██"
echo "  ██   ██ ██      ██      ██    ██ ████   ██  ██ ██ "
echo "  ██████  █████   ██      ██    ██ ██ ██  ██   ███  "
echo "  ██   ██ ██      ██      ██    ██ ██  ██ ██  ██ ██ "
echo "  ██   ██ ███████  ██████  ██████  ██   ████ ██   ██"
echo ""
echo "  Technieum Enterprise ASM  v2.0"
echo "  ─────────────────────────────────────────────────"
echo "  API:   http://localhost:${PORT}"
echo "  Docs:  http://localhost:${PORT}/docs"
echo "  UI:    http://localhost:${PORT}/"
echo "  ─────────────────────────────────────────────────"
echo ""

# ── Port conflict check ───────────────────────────────────────────────────────
_port_in_use() {
    ss -tlnp 2>/dev/null | grep -qE ":${PORT}[[:space:]]"
}
_kill_port() {
    local pids
    # Method 1: extract PIDs from ss -tlnp output (requires root or same user)
    pids=$(ss -tlnp 2>/dev/null | grep -E ":${PORT}[[:space:]]" | grep -oP 'pid=\K[0-9]+')
    if [[ -n "$pids" ]]; then
        echo "$pids" | xargs -r kill -9 2>/dev/null || true
        return 0
    fi
    # Method 2: fuser (may not be installed on minimal images)
    if command -v fuser &>/dev/null; then
        fuser -k "${PORT}/tcp" 2>/dev/null || true
        return 0
    fi
    # Method 3: lsof
    if command -v lsof &>/dev/null; then
        pids=$(lsof -ti ":${PORT}" 2>/dev/null)
        [[ -n "$pids" ]] && echo "$pids" | xargs -r kill -9 2>/dev/null || true
        return 0
    fi
}
if _port_in_use; then
    echo "[start] WARNING: Port ${PORT} is already in use. Killing existing process..."
    _kill_port
    # Wait up to 5 seconds for the port to be released
    for _i in 1 2 3 4 5; do
        sleep 1
        _port_in_use || break
    done
    if _port_in_use; then
        echo "[start] ERROR: Could not free port ${PORT}." >&2
        echo "[start]   Try manually: sudo kill -9 \$(ss -tlnp | grep ':${PORT}' | grep -oP 'pid=\K[0-9]+')" >&2
        exit 1
    fi
    echo "[start] Port ${PORT} is now free."
    echo ""
fi

# ── Database migrations ───────────────────────────────────────────────────────
echo "[start] Running database migrations..."
python3 -c "from app.db.database import apply_migrations; apply_migrations()"
echo "[start] Migrations complete."
echo ""

# ── Scan worker (background) ─────────────────────────────────────────────────
# Set TECHNIEUM_WORKER=false so the uvicorn process doesn't also spawn a thread.
echo "[start] Starting scan worker..."
TECHNIEUM_WORKER=false python3 -m app.workers.worker &
WORKER_PID=$!
echo "[start] Worker PID: ${WORKER_PID}"
echo ""

# ── Cleanup on exit ──────────────────────────────────────────────────────────
_cleanup() {
    echo ""
    echo "[start] Caught signal — shutting down..."
    if kill -0 "${WORKER_PID}" 2>/dev/null; then
        echo "[start] Stopping worker (PID ${WORKER_PID})..."
        kill "${WORKER_PID}" 2>/dev/null || true
        wait "${WORKER_PID}" 2>/dev/null || true
    fi
    echo "[start] Shutdown complete."
}
trap _cleanup INT TERM EXIT

# ── API server (foreground) ───────────────────────────────────────────────────
# TECHNIEUM_WORKER=false disables the built-in worker thread since the real worker
# is already running as a separate process above.
echo "[start] Starting API server on port ${PORT} (workers=${WORKERS})..."
TECHNIEUM_WORKER=false python3 -m uvicorn app.api.server:app \
    --host 0.0.0.0 \
    --port "${PORT}" \
    --workers "${WORKERS}" \
    --log-level info
