# Technieum Enterprise ASM Platform — Implementation Roadmap

**Document version:** 1.0  
**Status:** Planning  
**Audience:** Engineering, Security Platform, Product

This roadmap evolves the existing Technieum codebase into an enterprise Attack Surface Management (ASM) platform using an **incremental, non-breaking migration approach**. It is aligned with the target architecture and compatibility constraints defined in [ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md) and [MIGRATION_PLAN.md](MIGRATION_PLAN.md).

---

## 1. Current Repository Analysis

### 1.1 Repository Layout (As-Is)

| Path | Purpose | Reusability |
|------|---------|-------------|
| `technieum.py` | Main orchestrator; CLI entry; runs phases 1–4, parses outputs, updates DB | **Core** — extend with phases 0, 5–9 and flags |
| `db/database.py` | SQLite manager; WAL mode; schema init; bulk insert/query helpers | **Core** — extend schema via migrations only |
| `db/__init__.py` | Package marker | Keep |
| `parsers/parser.py` | Subdomain, HTTP, DNS, Port, URL, Directory, Vuln, Leak, Takeover parsers; `URL_TOOL_PARSERS` | **Core** — add new parser classes, do not break existing |
| `parsers/__init__.py` | Package marker | Keep |
| `modules/01_discovery.sh` – `04_vuln.sh` | Bash phase scripts; invoked by `technieum.py` with `(target, output_dir)` | **Must remain executable as-is**; optional enhancements |
| `lib/common.sh` | Shared bash utilities | Extend with new helpers (e.g. `call_python_module`, `send_notification`) |
| `config.yaml` | General, phase1–4, logging, output, notifications | Extend with new sections; preserve existing keys |
| `requirements.txt` | Python deps (pyyaml, dotenv, colorama, tqdm, tabulate, lxml) | Add new packages in optional/extras where possible |
| `docs/query.py` | Query CLI (--list, --summary, --subdomains, --vulns, --export, etc.) | **CLI** — preserve all flags/outputs; move to repo root for consistency |
| `tests/` | mock_data.py, test_database, test_parsers, test_integration | Extend; keep existing tests passing |
| `install.sh`, `setup.sh` | Environment and tool setup | Enhance for new optional tools; do not break current flow |

### 1.2 Reusable Components Summary

- **Bash phases:** `modules/01_discovery.sh` through `04_vuln.sh` — keep same invocation contract `(target, output_dir)` and output layout (e.g. `phase1_discovery/`, `phase2_intel/`, etc.).
- **Parser layer:** `parsers/parser.py` — all existing parsers and `URL_TOOL_PARSERS` remain; new parsers (Technology, ThreatIntel, Compliance, CVE, Cloud) added as new classes/functions.
- **DB manager:** `db/database.py` — existing tables and APIs unchanged; new tables added only via `db/migrations/` and applied optionally or on startup with version check.
- **CLI entry points:** `technieum.py` (existing flags/outputs preserved); `query.py` (all current flags and export formats preserved). New entry points: `monitor.py`, `report.py`, `admin.py` added alongside.

---

## 2. Target Architecture (Summary)

- **web/** — Static UI + lightweight server (e.g. FastAPI/Starlette static mount or separate small server).
- **api/** — FastAPI layer (scans, assets, findings, intel, reports, stream, webhooks).
- **Enhanced orchestrator** — `technieum.py` with Phase 0 (pre-scan), Phases 5–9 (threat intel, CVE/risk, change detection, compliance, graph), plus `--continuous`, `--api-server` (or separate API process).
- **intelligence/** — Python packages: scoring, correlation, delta, compliance, graph (invoked by bash or orchestrator).
- **db/migrations/** — Schema evolution (additive only for compatibility).
- **notifications/**, **reporting/**, **deployment/** — New subsystems with clear boundaries.

---

## 3. Phased Implementation Roadmap

### Phase A — Foundation & Guardrails (No Breaking Changes)

- **A.1** Document current behaviour: CLI flags, output paths, DB schema, parser contracts.
- **A.2** Introduce `db/migrations/` and migration runner; add version table; keep existing schema creation in `database.py` for new installs, migrations for existing DBs.
- **A.3** Add compatibility tests: existing CLI invocations (technieum.py, query.py) and module 01–04 runs produce same behaviour.
- **A.4** Move/copy `docs/query.py` to project root `query.py` (or symlink) so CLI usage matches docs; update docs to reference root `query.py`.

**Deliverables:** Migration framework, compatibility test suite, query.py at root.

---

### Phase B — Database & Config Evolution

- **B.1** Design and add new tables via migrations only: e.g. `service_inventory`, `technology_stack`, `asset_relationships`, `scan_baselines`, `threat_intelligence`, `remediation_tasks`, `compliance_checks`, `alert_rules`, `notification_log` (see complete_plan.md).
- **B.2** Extend `config.yaml` with new sections (phase0_prescan, phase5_threat_intel, phase6_risk_scoring, phase7_change_detection, phase8_compliance, phase9_attack_graph, notifications, continuous_monitoring, api_server); preserve all existing keys.
- **B.3** Optional: separate `api_keys.yaml` or `.env`-only for secrets; config references env vars.

**Deliverables:** Migration scripts, extended config schema doc, backward-compatible DB layer.

---

### Phase C — Intelligence Layer (Python Modules)

- **C.1** Create `intelligence/` package: `risk_scoring/`, `change_detection/`, `compliance/`, `graph/`, `threat_intel/` (and optionally `attribution/`).
- **C.2** Implement modules to be callable from bash (CLI args, JSON in/out) and importable from Python; no change to existing modules 01–04.
- **C.3** Add unit tests per subpackage; integration tests that run Python modules with fixture JSON.

**Deliverables:** `intelligence/*` packages, tests, documented CLI contracts for each script.

---

### Phase D — New Bash Phases & Orchestrator

- **D.1** Add `modules/00_prescan.sh` (Phase 0); keep 01–04 unchanged.
- **D.2** Add `modules/05_threat_intel.sh` through `09_attack_graph.sh`; each calls Python from `intelligence/` where needed.
- **D.3** Extend `technieum.py`: add phase dispatch for 0, 5–9; add `--phases` to accept 0–9; add `--continuous` and `--api-server` (or doc that API runs as separate process); preserve all existing flags and default `-p 1,2,3,4`.
- **D.4** Extend `scan_progress` (via migration) for phase0_done … phase9_done; ensure existing scans (phase1–4 only) still work.

**Deliverables:** New bash modules, extended technieum.py, phase 0–9 runnable with backward-compatible defaults.

---

### Phase E — Parsers & DB Wiring

- **E.1** Add new parsers in `parsers/parser.py`: e.g. TechnologyParser, ThreatIntelParser, ComplianceParser, CVEParser, CloudParser; keep all existing parsers.
- **E.2** Wire new phase outputs into orchestrator (parse_phase0_output … parse_phase9_output) and into DB via existing or new DB methods.
- **E.3** Extend `tests/mock_data.py` and integration tests for new phases.

**Deliverables:** New parsers, orchestrator parse methods, tests.

---

### Phase F — API & Web

- **F.1** Implement `api/` FastAPI app: routes for scans, assets, findings, intel, reports, stream (SSE), webhooks; Pydantic models; optional auth (API key / JWT) and rate limiting.
- **F.2** Implement `web/` static UI + lightweight server (or serve from API); dashboard, scan viewer, findings, graph viewer.
- **F.3** Document that SQLite remains default; API reads/writes same DB; no requirement to run API for CLI-only usage.

**Deliverables:** API server, web UI, deployment docs.

---

### Phase G — Notifications, Reporting, Deployment

- **G.1** Implement `notifications/` (channels: email, Slack, Teams, Discord, Telegram, webhook); alert manager and templates.
- **G.2** Implement `reporting/` (PDF, HTML, JSON, CSV, executive summary); visualization helpers.
- **G.3** Add `monitor.py`, `report.py`, `admin.py` CLIs; optional `scheduler.py` / state_manager for continuous mode.
- **G.4** Add deployment assets: Dockerfiles, docker-compose, systemd units, optional K8s manifests; scripts (backup, restore, health_check, migrate_db).

**Deliverables:** Notifications, reporting, new CLIs, deployment artifacts.

---

## 4. Compatibility Constraints

- **CLI:** Existing flags and outputs for `technieum.py` and `query.py` must continue to work. Default `-p 1,2,3,4`; new phases opt-in via `-p 0,1,2,3,4,5,6,7,8,9`.
- **Modules:** Existing `01_discovery.sh` through `04_vuln.sh` remain executable as-is; enhancements must be backward-compatible (e.g. new optional tools, same output paths).
- **SQLite:** Remains the default runtime DB; no mandatory external DB for core or API.
- **Config:** All existing `config.yaml` keys and sections remain valid; new sections additive.
- **Parsers:** Existing parser interfaces and file expectations unchanged; new parsers additive.

---

## 5. Dependency Impact Matrix

| Category | Package / Tool | Purpose | Required / Optional | Notes |
|----------|----------------|---------|---------------------|--------|
| **Existing** | pyyaml, python-dotenv, colorama, tqdm, tabulate, lxml | Config, CLI, parsers | Required | Already in requirements.txt |
| **API** | fastapi, uvicorn | API server | Optional (API mode) | Add to requirements-api or extras |
| **API** | pydantic, pydantic-settings | Schemas, config | Optional (API) | |
| **Intel** | requests, httpx | HTTP for NVD, EPSS, KEV, threat feeds | Optional (phases 5–6) | |
| **Risk/Graph** | networkx | Attack graph | Optional (phase 9) | |
| **Reporting** | reportlab, weasyprint, or markdown | PDF/reports | Optional (reporting) | |
| **Notifications** | (stdlib + requests) | Email, webhooks | Optional | Slack/Teams/Discord via webhooks |
| **Scheduler** | apscheduler | Continuous scans | Optional (monitor) | |
| **DB** | (sqlite3 stdlib) | Default DB | Required | No change |
| **Optional external** | Redis | Caching / state | Optional | Fallback to SQLite cache |
| **External tools** | See complete_plan.md | Nuclei, Nmap, etc. | Per-phase optional | No new mandatory system deps for phases 1–4 |
| **API keys** | Various (NVD, Shodan, etc.) | Threat intel, enrichment | Optional per source | Document in .env.example; failures non-fatal |

**Recommendation:** Keep `requirements.txt` minimal for CLI-only; add `requirements-api.txt` or `[api]` extra for API/web; document optional deps in INSTALLATION.md.

---

## 6. Milestone Checkpoints & Acceptance Criteria

| Milestone | Checkpoint | Acceptance Criteria |
|-----------|------------|---------------------|
| M1 — Foundation | After Phase A | All existing CLI commands and phases 1–4 run unchanged; migration runner exists; query.py at root. |
| M2 — Schema | After Phase B | New tables applied via migrations; existing DB opens and works; config backward-compatible. |
| M3 — Intelligence | After Phase C | All `intelligence.*` modules runnable from bash with JSON in/out; unit tests pass. |
| M4 — Phases 0,5–9 | After Phase D | `technieum.py -t example.com -p 0,1,2,3,4,5,6,7,8,9` runs without breaking 1–4; new bash modules exist. |
| M5 — Parsers | After Phase E | New phase outputs parsed and stored; existing parser tests and integration tests pass. |
| M6 — API/Web | After Phase F | API serves scans/assets/findings; web UI loads; CLI-only mode still default. |
| M7 — Full platform | After Phase G | Notifications, reports, monitor/report/admin CLIs, deployment assets documented. |

---

## 7. Risk Register

| ID | Risk | Category | Mitigation |
|----|------|----------|------------|
| R1 | Breaking existing CLI/scripts | Technical | Compatibility test suite; default phases 1–4; feature flags for new phases. |
| R2 | DB migration failure on existing DBs | Technical | Additive migrations only; version table; rollback scripts per migration (see MIGRATION_PLAN). |
| R3 | Performance regression (large scans) | Technical | Keep phase timeouts and threading model; benchmark before/after; optional chunking for huge targets. |
| R4 | Third-party API rate limits / TOS | Operational | Rate limiting in lib; configurable disable per source; document API keys and limits. |
| R5 | Legal/API TOS (scraping, GitHub, etc.) | Legal | Document acceptable use; optional modules; respect robots.txt and ToS in docs. |
| R6 | Secret leakage (API keys in config/logs) | Security | Secrets via env only; api_keys.yaml in .gitignore; audit logging without secrets. |
| R7 | Dependency supply chain | Operational | Pin versions; use venv; optional security scan in CI. |

---

## 8. Test Strategy Mapping

| Test Type | Scope | Where | Triggers |
|-----------|--------|--------|----------|
| **Unit** | Parsers, DB methods, intelligence.* pure functions | tests/test_parsers.py, test_database.py, tests/test_risk_scoring.py, etc. | Every commit / PR |
| **Integration** | Full phase 1–4 run (with mock or small target), new phases with fixtures | tests/test_integration.py, test_*_integration.py | PR, nightly |
| **E2E** | CLI invocations (technieum.py, query.py) end-to-end | tests/e2e/ or scripted | Release gate |
| **Perf** | Large target, phase timeouts, DB bulk inserts | tests/benchmark/ | Nightly / release |
| **Security** | SQL injection (query export), secret handling, auth on API | tests/test_security.py, manual | PR, release |
| **Compatibility** | Explicit “existing behaviour unchanged” tests | tests/test_compatibility.py | Every PR |

---

## 9. References

- [complete_plan.md](../complete_plan.md) — Detailed phase specs, directory layout, and examples.
- [ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md) — ADRs for technology and structure.
- [MIGRATION_PLAN.md](MIGRATION_PLAN.md) — Safe rollout and rollback per subsystem.
