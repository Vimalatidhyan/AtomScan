# Technieum — Change Log (production-hardening pass)

All changes are additive or corrective; no existing CLI flags, API routes,
or response shapes were altered.

## Files modified

| File | Change |
|------|--------|
| `modules/02_intel.sh` | Added `run_tool()` + counters; replaced hard `exit 1` on missing Phase 1 with graceful warning + empty-file fallback; updated summary log line |
| `modules/03_content.sh` | Same as 02: added `run_tool()`, counters, graceful fallback, summary log |
| `modules/04_vuln.sh` | Same as 02: added `run_tool()`, counters, graceful fallback, summary log |
| `technieum.py` | Added `--best-effort`/`--strict` CLI flags; implemented `--resume` (gates phase-skip on flag); wired `logging.level` from `config.yaml`; wired `general.output_dir` as default for `-o`; added `_early_config()` helper; added `resume`/`strict_mode` params to `Technieum.__init__` |
| `app/workers/worker.py` | Extended `_ingest_results()` with FFUF, HTTPx-alive, Feroxbuster/Dirsearch parsers; updated `_parse_nuclei` to handle both JSON array and JSONL formats |

## Files created

| File | Purpose |
|------|---------|
| `db/migrations/__init__.py` | Root-level migrations package exposing `run_migrations` |
| `db/migrations/runner.py` | Standalone SQL-file migration runner (scans `NNN_*.sql` in order) |
| `db/migrations/001_initial_enterprise.sql` | `CREATE TABLE IF NOT EXISTS` DDL for all 25 enterprise ORM tables — idempotent, SQLite-compatible |
| `requirements-api.txt` | API + worker Python dependencies separated from CLI-only `requirements.txt` |
| `tests/test_api_scan_cycle.py` | Pytest integration test: POST scan → verify DB rows → GET scan → GET targets |

## Files already correct (no changes needed)

| File | Status |
|------|--------|
| `lib/run_scan.sh` | Fully implemented (199 lines, phases 0–4, graceful tool fallback) |
| `app/api/middleware/auth.py` | `_key_cache`, `AUTH_CACHE_TTL`, `ensure_bootstrap_key` all present |
| `app/api/middleware/logging.py` | `configure_json_logging` present |
| `app/api/routes/assets.py` | All four asset endpoints present |
| `app/api/server.py` | All 8 routers mounted, `/api/health`, `/api/v1/bootstrap-key`, CORS, static files |
| `app/db/database.py` | `engine`, `SessionLocal`, `get_db`, `Database` class, `apply_migrations` all present |
| `app/api/routes/stream.py` | `Database` class import works correctly |
| `query.py` | Exists at repo root (284 lines) |
