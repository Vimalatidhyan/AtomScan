"""
Technieum API Server — entry-point shim.

The canonical server implementation lives in app/api/server.py.
This shim re-exports that app so that the original launch command works:

    uvicorn api.server:app --host 0.0.0.0 --port 8000

All API routes, authentication, rate limiting, CSRF protection, and
static web-UI routes are already registered in app/api/server.py.
"""

# Re-export the canonical, fully-featured application.
from app.api.server import app  # noqa: F401

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
