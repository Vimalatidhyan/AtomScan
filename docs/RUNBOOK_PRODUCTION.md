# Production Runbook — Technieum Enterprise

## Quick Reference

| Action | Command |
|--------|---------|
| Start all services | `docker compose -f deployment/docker/docker-compose.yml up -d` |
| Stop all services | `docker compose -f deployment/docker/docker-compose.yml down` |
| View API logs | `docker compose logs -f api` |
| View worker logs | `docker compose logs -f worker` |
| Health check | `curl http://localhost:8000/health` |
| Metrics | `curl -H "X-API-Key: $KEY" http://localhost:8000/api/v1/metrics/` |

---

## Initial Setup

1. Copy and populate env file:
   ```bash
   cp .env.production.example .env.production
   # Edit .env.production — fill in TECHNIEUM_SECRET_KEY, DATABASE_URL, etc.
   ```

2. Export env vars (or use --env-file):
   ```bash
   export $(grep -v '^#' .env.production | xargs)
   ```

3. Start services:
   ```bash
   docker compose -f deployment/docker/docker-compose.yml up -d
   ```

4. Verify health:
   ```bash
   curl http://localhost:8000/health
   # Expected: {"status":"healthy","version":"2.0.0","timestamp":"..."}
   ```

---

## Database Migrations

Migrations run automatically on API startup via `apply_migrations()`. They are
idempotent — safe to restart the API at any time.

To check migration status:
```bash
docker compose exec api python3 -c "
from app.db.database import engine
from app.db.migrations.runner import get_current_version
print('current version:', get_current_version(engine))
"
```

To manually roll back the latest migration:
```bash
docker compose exec api python3 -c "
from app.db.database import engine
from app.db.migrations.runner import rollback_last
rollback_last(engine)
print('rolled back')
"
```

---

## Upgrade Procedure

1. Pull new image:
   ```bash
   docker compose -f deployment/docker/docker-compose.yml pull
   ```

2. Restart with zero-downtime (API first, then worker):
   ```bash
   docker compose up -d --no-deps api
   # Wait for health check to pass
   docker compose up -d --no-deps worker
   ```

3. Verify health and metrics after upgrade.

---

## Rollback Procedure

1. Stop current containers:
   ```bash
   docker compose down
   ```

2. Tag the broken image and revert:
   ```bash
   docker tag technieum-api:latest technieum-api:broken-$(date +%Y%m%d)
   docker tag technieum-api:previous technieum-api:latest
   ```

3. Roll back database migration if schema changed:
   ```bash
   docker compose run --rm api python3 -c "
   from app.db.database import engine
   from app.db.migrations.runner import rollback_last
   rollback_last(engine)
   "
   ```

4. Restart:
   ```bash
   docker compose up -d
   ```

---

## Worker Management

The worker polls `scan_jobs` every `WORKER_POLL_SEC` seconds.

Check queue depth:
```bash
docker compose exec api python3 -c "
from app.db.database import engine
from sqlalchemy import text
with engine.connect() as c:
    r = c.execute(text('SELECT status, COUNT(*) FROM scan_jobs GROUP BY status'))
    for row in r: print(row[0], row[1])
"
```

Drain the queue manually (one-shot):
```bash
docker compose run --rm worker python -m app.workers.worker --drain
```

---

## Monitoring

**Structured JSON logs** are emitted to stdout. Ingest into your log aggregation
system (ELK, Loki, CloudWatch, etc.).

Key log fields:
- `req_id` — unique request ID
- `method`, `path`, `status`, `duration_ms` — HTTP request details
- `scan_run_id`, `job_id` — worker job fields
- `level`, `logger` — standard log fields

**Metrics endpoint** (`GET /api/v1/metrics/`):
Returns uptime, DB row counts by status, and auth cache stats.

---

## Security

- Rotate API keys via the `/api/v1/keys/` endpoint (or directly in DB).
- Rotate `TECHNIEUM_SECRET_KEY` by updating the env var and restarting the API
  (existing CSRF tokens will be invalidated; users must refresh).
- Rate limit: 1000 requests/hour per API key (configurable in `RateLimitMiddleware`).

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `503 Authentication service unavailable` | DB unreachable during auth | Check DATABASE_URL; verify DB is up |
| `401 Invalid API key format` | Key is not 32-64 alphanumeric chars | Re-generate key |
| `503` on all endpoints | Startup migration failed | Check logs for SQLAlchemy errors |
| Worker not processing jobs | Queue empty or worker down | Check `docker compose logs worker`; check scan_jobs table |
