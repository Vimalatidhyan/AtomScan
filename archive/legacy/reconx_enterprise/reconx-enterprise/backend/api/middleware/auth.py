"""API authentication middleware (API token + Bearer token)."""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from datetime import datetime
import hashlib
import logging

logger = logging.getLogger(__name__)
EXEMPT_PATHS = {"/health", "/version", "/docs", "/openapi.json", "/redoc"}


def hash_token(key: str) -> str:
    """Hash API token for storage comparison."""
    return hashlib.sha256(key.encode()).hexdigest()


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path in EXEMPT_PATHS or request.method == "OPTIONS":
            return await call_next(request)

        # Extract token from X-API-Key or Authorization: Bearer
        api_key = request.headers.get("X-API-Key") or \
            request.headers.get("Authorization", "").removeprefix("Bearer ").strip()

        if not api_key:
            return JSONResponse(
                {"detail": "API key required"},
                status_code=403
            )

        # Validate against database
        try:
            from backend.db.database import SessionLocal
            from backend.db.models import APIToken

            session = SessionLocal()
            token_hash = hash_token(api_key)

            try:
                token_obj = session.query(APIToken).filter(
                    APIToken.token_hash == token_hash,
                    APIToken.is_active == True,  # noqa: E712
                ).first()

                if not token_obj:
                    return JSONResponse({"detail": "Invalid API key"}, status_code=403)

                # Check expiration (compare both as naive UTC to avoid tz issues)
                if token_obj.expires_at:
                    exp = token_obj.expires_at
                    # Strip tz if present for safe comparison
                    if exp.tzinfo is not None:
                        exp = exp.replace(tzinfo=None)
                    if exp < datetime.utcnow():
                        return JSONResponse({"detail": "API key expired"}, status_code=403)

                # Update last used
                token_obj.last_used = datetime.utcnow()
                session.commit()

                request.state.user = token_obj.user_name
                request.state.token_type = token_obj.token_type
            finally:
                session.close()

        except Exception as e:
            logger.error(f"Auth middleware error: {e}")
            return JSONResponse({"detail": "Authentication service unavailable"}, status_code=503)

        return await call_next(request)


auth_middleware = AuthMiddleware
