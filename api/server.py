"""
ReconX API Server v2.0
Serves REST API and static web UI with FireCompass-style dashboard.
Run from project root: uvicorn api.server:app --host 0.0.0.0 --port 8000
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Project root (parent of api/)
ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = ROOT / "web" / "static"
ASSETS_DIR = STATIC_DIR / "assets"

app = FastAPI(
    title="ReconX Enterprise API",
    version="2.0",
    description="Attack Surface Management Platform",
)

# CORS — allow dashboard on same origin + dev servers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── API Routes ────────────────────────────────────────────────────────────────
from api.routes import scans, assets, findings, stream  # noqa: E402

app.include_router(scans.router, prefix="/api/v1")
app.include_router(assets.router, prefix="/api/v1")
app.include_router(findings.router, prefix="/api/v1")
app.include_router(stream.router, prefix="/api/v1")


# ─── Health ────────────────────────────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "reconx-api", "version": "2.0"}


# ─── Page Routes ───────────────────────────────────────────────────────────────
def _serve(filename: str):
    """Return an HTML page or JSON fallback."""
    p = STATIC_DIR / filename
    if p.exists():
        return FileResponse(p, media_type="text/html")
    return {"message": "ReconX API", "docs": "/docs"}


@app.get("/")
@app.get("/dashboard")
async def page_dashboard():
    return _serve("index.html")


@app.get("/assessments")
async def page_assessments():
    return _serve("scan_viewer_v2.html")


@app.get("/vulnerabilities")
async def page_vulnerabilities():
    return _serve("findings_v2.html")


@app.get("/graph")
async def page_graph():
    return _serve("graph_viewer_v2.html")


@app.get("/attack-surface")
async def page_attack_surface():
    return _serve("attack_surface_v2.html")


@app.get("/reports")
async def page_reports():
    return _serve("reports_v2.html")


@app.get("/compliance")
async def page_compliance():
    return _serve("compliance_v2.html")


@app.get("/alerts")
async def page_alerts():
    return _serve("alerts_v2.html")


@app.get("/settings")
async def page_settings():
    return _serve("settings_v2.html")


@app.get("/threat-intel")
async def page_threat_intel():
    return _serve("scan_viewer_v2.html")


# Legacy routes (v1 pages still in web/static/)
@app.get("/scan_viewer.html")
async def legacy_scan_viewer():
    return _serve("scan_viewer.html")


@app.get("/findings.html")
async def legacy_findings():
    return _serve("findings.html")


@app.get("/graph_viewer.html")
async def legacy_graph_viewer():
    return _serve("graph_viewer.html")


# ─── Static Assets (CSS, JS, images) ──────────────────────────────────────────
# IMPORTANT: must be mounted AFTER explicit routes so /assets/* doesn't shadow them
if ASSETS_DIR.exists():
    app.mount("/assets", StaticFiles(directory=ASSETS_DIR), name="assets")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
