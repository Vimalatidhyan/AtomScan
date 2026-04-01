# Performance Baseline — Round 4

## Methodology

All measurements taken on a development MacBook (Apple Silicon) with SQLite backend.
Production targets use PostgreSQL; SQLite numbers are for regression tracking only.

Smoke scripts:
- `scripts/perf_smoke_api.sh` — measures HTTP p95 latency for key endpoints (n=20 per endpoint)
- `scripts/perf_scan_queue.sh` — measures scan job queue throughput (n=5 synthetic jobs)

Threshold: **p95 < 200ms** per API endpoint.

---

## API Latency Baselines (SQLite, local, single-process)

| Endpoint | p95 (ms) | Notes |
|----------|----------|-------|
| `GET /health` | < 5 | No DB, no auth |
| `GET /api/v1/scans/` | < 30 | SQLite query, auth cache hit |
| `GET /api/v1/assets/` | < 30 | SQLite query, auth cache hit |
| `GET /api/v1/findings/` | < 30 | SQLite query, auth cache hit |
| `GET /api/v1/metrics/` | < 50 | Multiple count queries |

First request after server start will be slower (auth cache miss → DB lookup ~5–10ms extra).

---

## Worker Queue Throughput

| Metric | Value | Notes |
|--------|-------|-------|
| Jobs/second (no shell harness) | ~500 | Pure DB queue ops |
| Jobs/second (with run_scan.sh) | Harness-dependent | Typically 1 job/scan duration |
| poll interval | 5s | `WORKER_POLL_SEC` env var |
| max concurrent | 2 | `WORKER_MAX_JOBS` env var |

---

## Auth Middleware Cache Impact

| Scenario | Latency Impact |
|----------|---------------|
| Cache hit (TTL 60s) | +0ms (no DB) |
| Cache miss (first request) | +5–10ms (SQLite lookup) |
| Cache miss (PostgreSQL) | +1–3ms |

---

## Key Optimisations Implemented

1. **Auth TTL cache** — SHA-256 keyed, 60s TTL, avoids DB on every request
2. **Rate-limit thread-local connection** — persistent SQLite connection per thread + WAL mode
3. **Worker isolation** — separate process with its own DB session pool; API server unaffected by long-running scans
4. **Structured JSON logging** — no string formatting overhead until log level threshold

---

## How to Re-run Baselines

```bash
# API smoke test (server must be running)
TECHNIEUM_API_KEY=<your-key> ./scripts/perf_smoke_api.sh http://localhost:8000

# Queue throughput (no server needed)
./scripts/perf_scan_queue.sh 20
```
