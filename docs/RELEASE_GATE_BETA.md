# Release Gate — BETA

All items in this checklist must be ✅ before tagging a BETA release.

## Code Quality

- [ ] `python -m pytest -q` — 0 failures
- [ ] `python -m compileall -q app/ backend/` — exit 0
- [ ] `python -c "from sqlalchemy.orm import configure_mappers; import app.db.models; configure_mappers(); print('ok')"` — prints `ok`
- [ ] CI pipeline passes on `main` branch (all matrix jobs green)

## Security

- [ ] Gitleaks scan clean (`gitleaks detect --no-git -v`)
- [ ] No hardcoded secrets in `.env.*` example files
- [ ] `TECHNIEUM_SECRET_KEY` is ≥ 32 chars and randomly generated
- [ ] API keys in test fixtures are **not** reused in production
- [ ] CORS allowed origins do not include `*` (wildcard)

## Database

- [ ] `apply_migrations()` completes without error on a fresh database
- [ ] `apply_migrations()` is idempotent (safe to run twice)
- [ ] All 3 registered migrations are present in `schema_migrations` table

## Functionality

- [ ] `GET /health` returns `{"status": "healthy"}`
- [ ] API key authentication works (valid key → 200, invalid → 401, expired → 401)
- [ ] Rate limiting returns `429` after exceeding `requests_per_hour`
- [ ] CSRF protection returns `403` for state-changing requests without token
- [ ] SSE stream endpoint connects and delivers events
- [ ] Scan worker processes a queued job without error

## Deployment

- [ ] `docker compose -f deployment/docker/docker-compose.yml config` — validates without error
- [ ] `Dockerfile.api` builds successfully
- [ ] `Dockerfile.worker` builds successfully
- [ ] `.env.production.example` contains all required variables
- [ ] Health check passes in Docker (`curl http://localhost:8000/health`)

## Documentation

- [ ] `docs/API_BREAKING_CHANGES.md` is up to date
- [ ] `docs/RUNBOOK_PRODUCTION.md` covers start/stop/upgrade/rollback

---

**Sign-off**: _______________________  **Date**: ___________
