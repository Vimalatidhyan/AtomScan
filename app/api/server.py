"""FastAPI server for ReconX Enterprise v2.0.

Environment variables
---------------------
RECONX_SECRET_KEY       Required in production. Minimum 32 characters.
                        Used for CSRF token signing.
RECONX_ALLOWED_ORIGINS  Comma-separated CORS origins (default: localhost dev origins).
                        Example: "https://app.example.com,https://admin.example.com"
DATABASE_URL            SQLAlchemy DB URL (default: sqlite:///./reconx.db)
LOG_LEVEL               Logging verbosity (default: INFO)
"""
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import logging
import os
import secrets

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api.middleware.auth import AuthMiddleware
from app.api.middleware.rate_limit import RateLimitMiddleware
from app.api.middleware.logging import LoggingMiddleware, configure_json_logging
from app.api.middleware.csrf import CSRFMiddleware
from app.db.database import Database, apply_migrations

_LOG_LEVEL = getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
configure_json_logging(level=_LOG_LEVEL)
logger = logging.getLogger(__name__)

# ── CORS origins ─────────────────────────────────────────────────────────────
# Dev defaults allow localhost. In production, set RECONX_ALLOWED_ORIGINS.
_DEFAULT_DEV_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:8000",
    "http://localhost:8080",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:8000",
    "http://127.0.0.1:8080",
]
_allowed_origins_env = os.environ.get("RECONX_ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS = (
    [o.strip() for o in _allowed_origins_env.split(",") if o.strip()]
    if _allowed_origins_env
    else _DEFAULT_DEV_ORIGINS
)

# ── CSRF / secret key ─────────────────────────────────────────────────────────
_SECRET_KEY = os.environ.get("RECONX_SECRET_KEY", "")
if not _SECRET_KEY:
    _SECRET_KEY = secrets.token_urlsafe(32)
    logger.warning(
        "RECONX_SECRET_KEY not set — using a random ephemeral key. "
        "Set RECONX_SECRET_KEY in production for stable CSRF tokens."
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — startup and shutdown."""
    logger.info("ReconX Enterprise API v2.0 starting...", extra={"origins": ALLOWED_ORIGINS})
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
    yield
    logger.info("ReconX Enterprise API shutting down...")
    db.close()


app = FastAPI(
    title="ReconX Enterprise API",
    description="Attack Surface Management Platform v2.0",
    version="2.0.0",
    lifespan=lifespan,
)

# Middleware (order matters — outermost first)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware, requests_per_hour=1000)
app.add_middleware(CSRFMiddleware, secret_key=_SECRET_KEY)
app.add_middleware(LoggingMiddleware)
app.add_middleware(AuthMiddleware)

# Import and register routers
from app.api.routes import scans, assets, findings, intel, reports, stream, webhooks
from app.api.routes import metrics as metrics_router

app.include_router(scans.router, prefix="/api/v1/scans", tags=["scans"])
app.include_router(assets.router, prefix="/api/v1/assets", tags=["assets"])
app.include_router(findings.router, prefix="/api/v1/findings", tags=["findings"])
app.include_router(intel.router, prefix="/api/v1/intel", tags=["threat-intel"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["reports"])
app.include_router(stream.router, prefix="/api/v1/stream", tags=["streaming"])
app.include_router(webhooks.router, prefix="/api/v1/webhooks", tags=["webhooks"])
app.include_router(metrics_router.router, prefix="/api/v1/metrics", tags=["observability"])


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
    return {"version": "2.0.0", "name": "ReconX Enterprise"}


# ── Static web-UI routes ─────────────────────────────────────────────────────
# These are registered here so that `uvicorn app.api.server:app` works fully.
# The api/server.py shim also registers these (via re-export) for backward
# compatibility with the original launch command.
from pathlib import Path as _Path
from fastapi.staticfiles import StaticFiles as _StaticFiles
from fastapi.responses import FileResponse as _FileResponse

_ROOT = _Path(__file__).resolve().parents[2]
_STATIC_DIR = _ROOT / "web" / "static"
_ASSETS_DIR = _STATIC_DIR / "assets"


def _serve_page(filename: str):
    """Return a static HTML page, or JSON fallback when file is absent."""
    p = _STATIC_DIR / filename
    if p.exists():
        return _FileResponse(p, media_type="text/html")
    return {"message": "ReconX API — no UI found", "docs": "/docs"}


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


@app.get("/api/v1/bootstrap-key", include_in_schema=False)
async def get_bootstrap_key(request: Request):
    """Return bootstrap API key for first-time UI setup (dev only)."""
    key = getattr(request.app.state, 'bootstrap_api_key', None)
    if key:
        return {"key": key, "message": "Save this key in Settings. It won't be shown again after restart if RECONX_API_KEY is set."}
    return {"key": None, "message": "No bootstrap key. Create one with: python scripts/manage_keys.py create --name ui"}


# Static assets — mount after explicit routes
if _ASSETS_DIR.exists():
    app.mount("/assets", _StaticFiles(directory=str(_ASSETS_DIR)), name="assets")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
