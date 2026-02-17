#!/usr/bin/env bash
# ReconX Enterprise — single-command startup
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
echo "  ReconX Enterprise ASM  v2.0"
echo "  ─────────────────────────────────────────────────"
echo "  API:   http://localhost:${PORT}"
echo "  Docs:  http://localhost:${PORT}/docs"
echo "  UI:    http://localhost:${PORT}/"
echo "  ─────────────────────────────────────────────────"
echo ""

# ── Database migrations ───────────────────────────────────────────────────────
echo "[start] Running database migrations..."
python -c "from app.db.database import apply_migrations; apply_migrations()"
echo "[start] Migrations complete."
echo ""

# ── Scan worker (background) ─────────────────────────────────────────────────
# Set RECONX_WORKER=false so the uvicorn process doesn't also spawn a thread.
echo "[start] Starting scan worker..."
RECONX_WORKER=false python -m app.workers.worker &
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
# RECONX_WORKER=false disables the built-in worker thread since the real worker
# is already running as a separate process above.
echo "[start] Starting API server on port ${PORT} (workers=${WORKERS})..."
RECONX_WORKER=false python -m uvicorn app.api.server:app \
    --host 0.0.0.0 \
    --port "${PORT}" \
    --workers "${WORKERS}" \
    --log-level info
