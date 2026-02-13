"""CSRF protection middleware."""
import secrets
import hashlib
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.datastructures import MutableHeaders
from typing import Callable


class CSRFMiddleware(BaseHTTPMiddleware):
    """CSRF protection for state-changing operations.
    
    Generates CSRF tokens for GET requests and validates them for
    POST/PUT/PATCH/DELETE requests.
    """
    
    def __init__(self, app, secret_key: str = None):
        super().__init__(app)
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        # Exempt routes that don't need CSRF (public APIs, webhooks)
        self.exempt_paths = [
            "/api/webhooks/",  # Webhook endpoints
            "/api/stream/",    # SSE endpoints
            "/docs",           # OpenAPI docs
            "/redoc", 
            "/openapi.json"
        ]
    
    async def dispatch(self, request: Request, call_next: Callable):
        """Check CSRF token for state-changing requests."""
        
        # Skip CSRF for exempt paths
        if any(request.url.path.startswith(path) for path in self.exempt_paths):
            return await call_next(request)
        
        # Skip CSRF for safe methods
        if request.method in ["GET", "HEAD", "OPTIONS"]:
            # Generate and attach CSRF token for GET requests
            token = self._generate_token()
            response = await call_next(request)
            response.headers["X-CSRF-Token"] = token
            return response
        
        # Validate CSRF token for state-changing methods
        if request.method in ["POST", "PUT", "PATCH", "DELETE"]:
            token = request.headers.get("X-CSRF-Token")
            if not token:
                raise HTTPException(
                    status_code=403,
                    detail="CSRF token missing. Include X-CSRF-Token header."
                )
            
            if not self._validate_token(token):
                raise HTTPException(
                    status_code=403,
                    detail="Invalid CSRF token"
                )
        
        return await call_next(request)
    
    def _generate_token(self) -> str:
        """Generate a CSRF token."""
        random_part = secrets.token_urlsafe(16)
        # HMAC the random part with secret key
        h = hashlib.sha256()
        h.update(self.secret_key.encode())
        h.update(random_part.encode())
        signature = h.hexdigest()[:16]
        return f"{random_part}.{signature}"
    
    def _validate_token(self, token: str) -> bool:
        """Validate a CSRF token."""
        try:
            parts = token.split(".")
            if len(parts) != 2:
                return False
            
            random_part, signature = parts
            # Re-compute signature
            h = hashlib.sha256()
            h.update(self.secret_key.encode())
            h.update(random_part.encode())
            expected_sig = h.hexdigest()[:16]
            
            # Constant-time comparison
            return secrets.compare_digest(signature, expected_sig)
        except Exception:
            return False
