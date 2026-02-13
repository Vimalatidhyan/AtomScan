"""API authentication middleware (API key + Bearer token)."""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from datetime import datetime
import hashlib
import logging

logger = logging.getLogger(__name__)
EXEMPT_PATHS = {"/health", "/version", "/docs", "/openapi.json", "/redoc"}

def hash_api_key(key: str) -> str:
    """Hash API key for storage comparison."""
    return hashlib.sha256(key.encode()).hexdigest()

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path in EXEMPT_PATHS or request.method == "OPTIONS":
            return await call_next(request)
        
        # Extract API key from headers
        api_key = request.headers.get("X-API-Key") or request.headers.get("Authorization", "").removeprefix("Bearer ")
        
        if not api_key:
            return JSONResponse({"detail": "Unauthorized - API key required"}, status_code=401)
        
        # Validate format (alphanumeric, 32-64 chars)
        if not api_key.isalnum() or not (32 <= len(api_key) <= 64):
            return JSONResponse({"detail": "Invalid API key format"}, status_code=401)
        
        # Validate against database (if available)
        try:
            from backend.db.database import Database
            from backend.db.models import APIKey
            
            db = Database()
            db.connect()
            key_hash = hash_api_key(api_key)
            
            api_key_obj = db.session.query(APIKey).filter(
                APIKey.key_hash == key_hash,
                APIKey.is_active == True
            ).first()
            
            if not api_key_obj:
                db.close()
                return JSONResponse({"detail": "Invalid API key"}, status_code=401)
            
            # Check expiration
            if api_key_obj.expires_at and api_key_obj.expires_at < datetime.utcnow():
                db.close()
                return JSONResponse({"detail": "API key expired"}, status_code=401)
            
            # Update last used timestamp
            api_key_obj.last_used = datetime.utcnow()
            db.session.commit()
            db.close()
            
            # Attach user info to request
            request.state.user = api_key_obj.user_identifier
            request.state.api_key_name = api_key_obj.name
            
        except Exception as e:
            logger.error(f"Auth middleware error: {e}")
            return JSONResponse({"detail": "Authentication service unavailable"}, status_code=503)
        
        return await call_next(request)

auth_middleware = AuthMiddleware
