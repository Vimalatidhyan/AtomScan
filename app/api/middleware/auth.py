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
BOOTSTRAP_KEY: Optional[str] = os.environ.get("RECONX_API_KEY")


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
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        # Exempt: health/version/docs, UI pages, static assets, OPTIONS preflight
        # Also exempt SSE stream endpoints (read-only, EventSource can't send headers)
        if (path in EXEMPT_PATHS
                or request.method == "OPTIONS"
                or path.startswith(_UI_PREFIXES)
                or path.startswith(_EXEMPT_API_PREFIXES)
                or not path.startswith(_PROTECTED_PREFIX)):
            return await call_next(request)

        # Extract API key from headers or query param (needed for EventSource)
        api_key = (
            request.headers.get("X-API-Key")
            or request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            or request.query_params.get("api_key", "")
        )

        if not api_key:
            return JSONResponse({"detail": "Unauthorized - API key required"}, status_code=401)

        # Validate format (alphanumeric, 32-64 chars)
        if not api_key.isalnum() or not (32 <= len(api_key) <= 64):
            return JSONResponse({"detail": "Invalid API key format"}, status_code=401)

        key_hash = hash_api_key(api_key)

        # Fast path: check in-process cache first
        cached = _cache_lookup(key_hash)
        if cached:
            user, name, expires_at = cached
            if expires_at and expires_at < datetime.now(timezone.utc):
                del _key_cache[key_hash]
                return JSONResponse({"detail": "API key expired"}, status_code=401)
            request.state.user = user
            request.state.api_key_name = name
            return await call_next(request)

        # Slow path: validate against database
        try:
            from app.db.database import SessionLocal
            from app.db.models import APIKey

            db = SessionLocal()
            try:
                api_key_obj = db.query(APIKey).filter(
                    APIKey.key_hash == key_hash,
                    APIKey.is_active == True,
                ).first()

                if not api_key_obj:
                    return JSONResponse({"detail": "Invalid API key"}, status_code=401)

                expires_raw = api_key_obj.expires_at
                if expires_raw is not None:
                    if expires_raw.tzinfo is None:
                        expires_raw = expires_raw.replace(tzinfo=timezone.utc)
                if expires_raw and expires_raw < datetime.now(timezone.utc):
                    return JSONResponse({"detail": "API key expired"}, status_code=401)

                # Update last_used without a separate query round-trip
                api_key_obj.last_used = datetime.now(timezone.utc)
                db.commit()

                user = api_key_obj.user_identifier
                name = api_key_obj.name
                # Normalize to tz-aware for consistent cache comparisons
                expires_at = expires_raw
            finally:
                db.close()

            # Populate cache and request state
            _cache_store(key_hash, user, name, expires_at)
            request.state.user = user
            request.state.api_key_name = name

        except Exception as e:
            logger.error(f"Auth middleware error: {e}")
            return JSONResponse({"detail": "Authentication service unavailable"}, status_code=503)

        return await call_next(request)


auth_middleware = AuthMiddleware
