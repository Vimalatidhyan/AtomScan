# Backend Hardening Report — Round 3

## Status: PASS

All Round 3 gates passed on 2026-02-16.

---

## Gate Results

| # | Command | Result |
|---|---------|--------|
| 1 | `configure_mappers()` — no backref collision | ✅ ok |
| 2 | `pytest -q` (full suite) | ✅ 139 passed |
| 3 | `pytest -q tests/` | ✅ 30 passed |
| 4 | `pytest -q backend/tests/test_api.py` (ini enforces `error::DeprecationWarning:app,backend`) | ✅ 25 passed |
| 5 | `python3 -m compileall -q app/ backend/` | ✅ exit 0 |

---

## Changes Made This Round

### 1. Versioned Migration Framework (`app/db/migrations/`)

Custom Alembic-compatible migration runner implemented without the Alembic package (SSL cert issue prevented pip install in this environment).

- `app/db/migrations/runner.py` — registry + `run_migrations()` + `rollback_last()`
- `app/db/migrations/versions.py` — 3 migrations registered:
  - `001` — Baseline schema (all tables via `create_all`)
  - `002` — Add `vulnerabilities.status VARCHAR(50) DEFAULT 'open'`
  - `003` — ORM backref rename (Python-only, no DDL)
- `app/db/database.py` — `apply_migrations()` wired into startup

Migrations are idempotent: "already exists" / "duplicate column" errors are silently skipped.

### 2. SQLAlchemy Mapper Stability

`ComplianceEvidence.compliance_finding` relationship backref renamed from `"evidence"` → `"compliance_evidence_items"` to eliminate the `InvalidRequestError: property 'evidence' on mapper ... conflicts with existing property` crash.

### 3. Datetime Timezone Normalization (auth.py)

SQLite stores `DateTime` columns as timezone-naive. `auth.py` now normalizes the value on read:

```python
if expires_raw.tzinfo is None:
    expires_raw = expires_raw.replace(tzinfo=timezone.utc)
```

This eliminates the `can't compare offset-naive and offset-aware datetimes` 503 error that affected all authenticated endpoints during testing.

### 4. `datetime.utcnow()` Deprecation Eliminated

All occurrences replaced with `datetime.now(timezone.utc)` in `app/api/middleware/auth.py`. pytest.ini now enforces `error::DeprecationWarning:app` and `error::DeprecationWarning:backend` so future regressions fail CI immediately.

### 5. Scoped DeprecationWarning Enforcement

`pytest.ini` `filterwarnings` section:

```ini
filterwarnings =
    error::DeprecationWarning:app
    error::DeprecationWarning:backend
    ignore::DeprecationWarning:sqlalchemy
    ignore::DeprecationWarning:pytest_asyncio
    ignore::DeprecationWarning:asyncio
```

Note: The global `-W error::DeprecationWarning` Python flag is incompatible with `pytest_asyncio` on Python 3.14+ because `pytest_asyncio` imports `asyncio.AbstractEventLoopPolicy` (deprecated in 3.14, removed in 3.16) during plugin loading — before pytest can apply its own filters. The scoped ini approach is the correct solution.

---

## Security Items Addressed

| Item | Fix |
|------|-----|
| Auth middleware opened DB on every request | 60s in-process TTL cache; DB only hit on cache miss |
| Rate-limit middleware opened/closed connection per request | Thread-local persistent connections + WAL mode |
| CSRF exempt paths used wrong prefix | Updated to `/api/v1/webhooks/`, `/api/v1/stream/` |
| CSRF checked unnecessarily for API-key requests | Added bypass for `X-API-Key` / `Authorization: Bearer` headers |
| Nuclei template update ran unconditionally on every scan | Gated on `TECHNIEUM_NUCLEI_UPDATE=true` env var |
