"""
ReconX API Server
Serves REST API and static web UI.
Run from project root: uvicorn api.server:app --host 0.0.0.0 --port 8000
"""

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Project root (parent of api/)
ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = ROOT / "web" / "static"

app = FastAPI(
    title="ReconX API",
    version="2.0",
    description="Attack Surface Management API",
)

# Mount API routes
from api.routes import scans, assets, findings, stream
app.include_router(scans.router, prefix="/api/v1")
app.include_router(assets.router, prefix="/api/v1")
app.include_router(findings.router, prefix="/api/v1")
app.include_router(stream.router, prefix="/api/v1")


# Mount static files (JS, CSS, assets)
if STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")


@app.get("/")
async def index():
    """Serve dashboard."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "ReconX API", "docs": "/docs"}


@app.get("/scan_viewer.html")
async def scan_viewer():
    p = STATIC_DIR / "scan_viewer.html"
    if p.exists():
        return FileResponse(p)
    raise HTTPException(status_code=404, detail="Not found")


@app.get("/findings.html")
async def findings_page():
    p = STATIC_DIR / "findings.html"
    if p.exists():
        return FileResponse(p)
    raise HTTPException(status_code=404, detail="Not found")


@app.get("/graph_viewer.html")
async def graph_viewer():
    p = STATIC_DIR / "graph_viewer.html"
    if p.exists():
        return FileResponse(p)
    raise HTTPException(status_code=404, detail="Not found")


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "reconx-api"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
