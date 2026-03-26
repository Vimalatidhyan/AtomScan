"""FastAPI server for Technieum Enterprise v2.0.

Environment variables
---------------------
TECHNIEUM_ALLOWED_ORIGINS  Comma-separated CORS origins (default: localhost dev origins).
DATABASE_URL            SQLAlchemy DB URL (default: sqlite:///./technieum.db)
LOG_LEVEL               Logging verbosity (default: INFO)
"""
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import logging
import os
import threading

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api.middleware.auth import AuthMiddleware
from app.api.middleware.logging import LoggingMiddleware, configure_json_logging
from app.db.database import Database, apply_migrations

_LOG_LEVEL = getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
configure_json_logging(level=_LOG_LEVEL)
logger = logging.getLogger(__name__)

# ── CORS origins ─────────────────────────────────────────────────────────────
# Dev defaults allow localhost. In production, set TECHNIEUM_ALLOWED_ORIGINS.
_DEFAULT_DEV_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:8000",
    "http://localhost:8080",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:8000",
    "http://127.0.0.1:8080",
]
_allowed_origins_env = os.environ.get("TECHNIEUM_ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS = (
    [o.strip() for o in _allowed_origins_env.split(",") if o.strip()]
    if _allowed_origins_env
    else _DEFAULT_DEV_ORIGINS
)

# When TECHNIEUM_WORKER=true (default), the server starts the scan worker as a
# daemon thread so `uvicorn app.api.server:app` is the only command needed.
# Set TECHNIEUM_WORKER=false when running the worker as a separate process (e.g.
# via start.sh) to avoid double-claiming jobs.
_EMBED_WORKER = os.environ.get("TECHNIEUM_WORKER", "true").lower() in ("true", "1", "yes")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — startup and shutdown."""
    logger.info("Technieum Enterprise API v2.0 starting...", extra={"origins": ALLOWED_ORIGINS})
    apply_migrations()
    db = Database()
    db.connect()
    app.state.db = db

    # Auto-create bootstrap API key if none exists
    from app.api.middleware.auth import ensure_bootstrap_key
    bootstrap_key = ensure_bootstrap_key()
    if bootstrap_key:
        app.state.bootstrap_api_key = bootstrap_key
        logger.info("Bootstrap API key available. Use it in Settings or via X-API-Key header.")

    # Optionally start the scan worker as an embedded background thread.
    # The thread is daemon=True so it is killed automatically when the server exits.
    _worker_thread: threading.Thread | None = None
    if _EMBED_WORKER:
        try:
            from app.workers.worker import run_forever as _worker_run_forever
            _worker_thread = threading.Thread(
                target=_worker_run_forever,
                name="technieum-worker",
                daemon=True,
            )
            _worker_thread.start()
            logger.info("Embedded scan worker started (TECHNIEUM_WORKER=true). "
                        "Set TECHNIEUM_WORKER=false to disable.")
        except Exception as exc:  # pragma: no cover
            logger.warning("Could not start embedded worker: %s", exc)
    else:
        logger.info("Embedded worker disabled (TECHNIEUM_WORKER=false).")

    yield

    logger.info("Technieum Enterprise API shutting down...")
    db.close()
    # _worker_thread is daemon — OS cleans it up on process exit


app = FastAPI(
    title="Technieum Enterprise API",
    description="Attack Surface Management Platform v2.0",
    version="2.0.0",
    lifespan=lifespan,
)

# Middleware (order matters — outermost first). CSRF and rate-limit removed for simpler UI/backend connectivity.
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(LoggingMiddleware)
app.add_middleware(AuthMiddleware)

# Import and register routers
from app.api.routes import scans, assets, findings, intel, reports, stream, webhooks  # noqa: E402
from app.api.routes import metrics as metrics_router  # noqa: E402
from app.api.routes import subdomain_lookup  # noqa: E402
from app.api.routes import assessment as assessment_router  # noqa: E402

app.include_router(scans.router, prefix="/api/v1/scans", tags=["scans"])
app.include_router(assets.router, prefix="/api/v1/assets", tags=["assets"])
app.include_router(findings.router, prefix="/api/v1/findings", tags=["findings"])
app.include_router(intel.router, prefix="/api/v1/intel", tags=["threat-intel"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["reports"])
app.include_router(stream.router, prefix="/api/v1/stream", tags=["streaming"])
app.include_router(webhooks.router, prefix="/api/v1/webhooks", tags=["webhooks"])
app.include_router(metrics_router.router, prefix="/api/v1/metrics", tags=["observability"])
app.include_router(subdomain_lookup.router, prefix="/api/v1/subdomains", tags=["subdomain-discovery"])
app.include_router(assessment_router.router, prefix="/api/assessment", tags=["assessment"])


@app.get("/health", tags=["system"])
async def health_check():
    """Health check endpoint (no auth required)."""
    return {
        "status": "healthy",
        "version": "2.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/health", tags=["system"], include_in_schema=False)
async def health_check_compat():
    """Compatibility alias for /health — some UI versions call /api/health."""
    return await health_check()


@app.get("/version", tags=["system"])
async def version():
    """Version endpoint."""
    return {"version": "2.0.0", "name": "Technieum Enterprise"}


# ── Static web-UI routes ─────────────────────────────────────────────────────
# These are registered here so that `uvicorn app.api.server:app` works fully.
# The api/server.py shim also registers these (via re-export) for backward
# compatibility with the original launch command.
from pathlib import Path as _Path  # noqa: E402
from fastapi.staticfiles import StaticFiles as _StaticFiles  # noqa: E402
from fastapi.responses import FileResponse as _FileResponse  # noqa: E402

_ROOT = _Path(__file__).resolve().parents[2]
# UI files live in scripts/web/static/ (the canonical location in this repo)
_STATIC_DIR = _ROOT / "scripts" / "web" / "static"
_ASSETS_DIR = _STATIC_DIR / "assets"


def _serve_page(filename: str):
    """Return a static HTML page, or JSON fallback when file is absent."""
    p = _STATIC_DIR / filename
    if p.exists():
        return _FileResponse(p, media_type="text/html")
    return {"message": "Technieum API — no UI found", "docs": "/docs"}


@app.get("/", include_in_schema=False)
@app.get("/dashboard", include_in_schema=False)
async def _page_dashboard():
    return _serve_page("index.html")


@app.get("/assessments", include_in_schema=False)
async def _page_assessments():
    return _serve_page("scan_viewer_v2.html")


@app.get("/vulnerabilities", include_in_schema=False)
async def _page_vulnerabilities():
    return _serve_page("findings_v2.html")


@app.get("/graph", include_in_schema=False)
async def _page_graph():
    return _serve_page("graph_viewer_v2.html")


@app.get("/attack-surface", include_in_schema=False)
async def _page_attack_surface():
    return _serve_page("attack_surface_v2.html")


@app.get("/reports-ui", include_in_schema=False)
@app.get("/reports", include_in_schema=False)
async def _page_reports():
    return _serve_page("reports_v2.html")


@app.get("/compliance", include_in_schema=False)
async def _page_compliance():
    return _serve_page("compliance_v2.html")


@app.get("/alerts", include_in_schema=False)
async def _page_alerts():
    return _serve_page("alerts_v2.html")


@app.get("/settings", include_in_schema=False)
async def _page_settings():
    return _serve_page("settings_v2.html")


@app.get("/threat-intel", include_in_schema=False)
async def _page_threat_intel():
    return _serve_page("threat_intel_v2.html")


@app.get("/subdomain-finder", include_in_schema=False)
async def _page_subdomain_finder():
    return _serve_page("subdomain_finder.html")


@app.get("/api/v1/bootstrap-key", include_in_schema=False)
async def get_bootstrap_key(request: Request):
    """Return bootstrap API key for first-time UI setup (dev only)."""
    key = getattr(request.app.state, 'bootstrap_api_key', None)
    if key:
        return {"key": key, "message": "Save this key in Settings. It won't be shown again after restart if TECHNIEUM_API_KEY is set."}
    return {"key": None, "message": "No bootstrap key. Create one with: python scripts/manage_keys.py create --name ui"}


# Static assets — mount after explicit routes
if _ASSETS_DIR.exists():
    app.mount("/assets", _StaticFiles(directory=str(_ASSETS_DIR)), name="assets")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")  # nosec B104
