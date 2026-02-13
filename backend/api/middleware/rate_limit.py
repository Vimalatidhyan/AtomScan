"""Persistent rate limiting middleware with SQLite storage."""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from datetime import datetime, timedelta, timezone
import logging
import sqlite3
import os
from pathlib import Path

logger = logging.getLogger(__name__)
EXEMPT_PATHS = {"/health", "/version", "/docs", "/openapi.json", "/redoc"}

class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, requests_per_hour: int = 1000):
        super().__init__(app)
        self._limit = requests_per_hour
        self._db_path = self._init_db()

    def _init_db(self) -> str:
        """Initialize SQLite database for rate limiting."""
        # Use project's data directory
        db_dir = Path(__file__).parent.parent.parent.parent / "data"
        db_dir.mkdir(exist_ok=True)
        db_path = str(db_dir / "rate_limits.db")
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_key_timestamp ON rate_limits(key, timestamp)")
        conn.commit()
        conn.close()
        
        logger.info(f"Rate limit database initialized at {db_path}")
        return db_path

    def _cleanup_old_entries(self, conn: sqlite3.Connection, key: str, window_start: datetime):
        """Remove entries older than the sliding window."""
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM rate_limits WHERE key = ? AND timestamp < ?",
            (key, window_start.isoformat())
        )
        conn.commit()

    def _get_request_count(self, conn: sqlite3.Connection, key: str, window_start: datetime) -> int:
        """Get number of requests within the time window."""
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM rate_limits WHERE key = ? AND timestamp >= ?",
            (key, window_start.isoformat())
        )
        return cursor.fetchone()[0]

    def _record_request(self, conn: sqlite3.Connection, key: str, timestamp: datetime):
        """Record a new request."""
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO rate_limits (key, timestamp) VALUES (?, ?)",
            (key, timestamp.isoformat())
        )
        conn.commit()

    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for exempt paths
        if request.url.path in EXEMPT_PATHS:
            return await call_next(request)

        # Use API key or client IP as identifier
        key = request.headers.get("X-API-Key", request.client.host if request.client else "unknown")
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(hours=1)

        conn = None
        try:
            conn = sqlite3.connect(self._db_path)
            
            # Cleanup old entries periodically (every ~10th request for efficiency)
            import random
            if random.randint(1, 10) == 1:
                self._cleanup_old_entries(conn, key, window_start)

            # Check current rate
            count = self._get_request_count(conn, key, window_start)

            if count >= self._limit:
                return JSONResponse(
                    {"detail": "Rate limit exceeded", "limit": self._limit, "window": "1 hour"},
                    status_code=429,
                    headers={"Retry-After": "3600"}
                )

            # Record this request
            self._record_request(conn, key, now)

            # Process request
            response = await call_next(request)
            
            # Add rate limit headers
            remaining = max(0, self._limit - count - 1)
            response.headers["X-RateLimit-Limit"] = str(self._limit)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            response.headers["X-RateLimit-Reset"] = (now + timedelta(hours=1)).isoformat()
            
            return response

        except Exception as e:
            logger.error(f"Rate limiting error: {e}")
            # On error, allow the request to proceed
            return await call_next(request)
        finally:
            if conn:
                conn.close()

rate_limit_middleware = RateLimitMiddleware
