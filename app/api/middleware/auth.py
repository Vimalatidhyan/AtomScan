"""API authentication middleware (API key + Bearer token).

Performance improvement: recently validated keys are cached in-process for
AUTH_CACHE_TTL seconds so the database is not hit on every request.
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from datetime import datetime, timezone
import hashlib
import logging
import os
import time
from typing import Optional, Tuple

logger = logging.getLogger(__name__)
# Paths always exempt from API key auth
EXEMPT_PATHS = {"/health", "/api/health", "/version", "/docs", "/openapi.json", "/redoc", "/api/v1/bootstrap-key"}

# Path prefixes for UI pages (no auth needed — static HTML)
_UI_PREFIXES = ("/assets/", "/static/")

# Path prefixes that are exempt from auth (read-only SSE streams)
_EXEMPT_API_PREFIXES = ("/api/v1/stream/",)

# Only paths under this prefix require API key authentication
_PROTECTED_PREFIX = "/api/v1/"

# In-memory cache: key_hash -> (user_identifier, key_name, expires_at, cache_until)
_key_cache: dict = {}
AUTH_CACHE_TTL = 60  # seconds

# Bootstrap API key — set via env var or auto-generated on first startup
BOOTSTRAP_KEY: Optional[str] = os.environ.get("TECHNIEUM_API_KEY")


def hash_api_key(key: str) -> str:
    """Hash API key for storage comparison."""
    return hashlib.sha256(key.encode()).hexdigest()


def _cache_lookup(key_hash: str) -> Optional[Tuple[str, str, Optional[datetime]]]:
    """Return (user_identifier, name, expires_at) from cache if still valid, else None."""
    entry = _key_cache.get(key_hash)
    if entry and time.monotonic() < entry[3]:
        return entry[0], entry[1], entry[2]
    return None


def _cache_store(key_hash: str, user: str, name: str, expires_at: Optional[datetime]) -> None:
    _key_cache[key_hash] = (user, name, expires_at, time.monotonic() + AUTH_CACHE_TTL)


def ensure_bootstrap_key() -> Optional[str]:
    """Create a bootstrap API key in DB on every startup. Returns the raw key or None."""
    global BOOTSTRAP_KEY
    if BOOTSTRAP_KEY:
        return BOOTSTRAP_KEY
    try:
        import secrets
        from app.db.database import SessionLocal
        from app.db.models import APIKey
        db = SessionLocal()
        try:
            # Generate a 32-char alphanumeric key
            raw_key = secrets.token_hex(16)  # 32 hex chars, all alphanumeric
            key_hash = hash_api_key(raw_key)
            api_key = APIKey(
                key_hash=key_hash,
                name="bootstrap",
                user_identifier="admin",
            )
            db.add(api_key)
            db.commit()
            BOOTSTRAP_KEY = raw_key
            logger.info(
                "Bootstrap API key created. "
                "Set it in your browser Settings page or use: X-API-Key: %s",
                raw_key,
            )
            return raw_key
        finally:
            db.close()
    except Exception as e:
        logger.warning("Could not create bootstrap key: %s", e)
        return None


class AuthMiddleware(BaseHTTPMiddleware):
    """API key auth is disabled — all requests are allowed. Kept for optional re-enable later."""

    async def dispatch(self, request: Request, call_next):
        # Auth disabled: always pass through (no API key required)
        request.state.user = getattr(request.state, "user", "anonymous")
        request.state.api_key_name = getattr(request.state, "api_key_name", None)
        return await call_next(request)


auth_middleware = AuthMiddleware
