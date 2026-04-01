# Technieum Enterprise ASM — Migration Plan

**Safe rollout and rollback per subsystem**

This document defines how to roll out and roll back each subsystem so that the migration remains non-breaking and reversible at every step. It should be read together with [ENTERPRISE_ROADMAP.md](ENTERPRISE_ROADMAP.md) and [ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md).

---

## 1. Principles

- **Additive first:** New code paths are opt-in (new phases, new CLI commands, new API).
- **Backward compatibility:** Existing CLI, modules 01–04, and DB usage continue to work.
- **Rollback per subsystem:** Each subsystem can be disabled or reverted without reverting the whole platform.
- **Database:** Migrations are additive; rollback = restore DB backup + revert code, or run down-migration if provided.

---

## 2. Subsystem Rollout & Rollback

### 2.1 Database Migrations (`db/migrations/`)

| Aspect | Rollout | Rollback |
|--------|---------|----------|
| **What** | Add `db/migrations/` and a version table; add migration scripts (e.g. 001_add_service_tables.sql, 002_add_relationships.sql). On startup (or via `migrate_db.sh`), run unapplied migrations in order. | **Safe rollback:** Restore DB from backup taken before migration. **Optional:** Provide down-migration scripts (e.g. 001_down.sql) that drop only the new objects; run in reverse order. |
| **Verification** | After migration: existing queries (subdomains, urls, vulnerabilities, etc.) still work; new tables exist and are empty. | After rollback: same queries work; new tables gone (if down-migration) or ignored by reverted code. |
| **Risk** | Migration script bug (e.g. syntax error, constraint failure). | Down-migration drops data in new tables. |

**Recommendation:** Take a DB backup before first migration in each environment. Document backup/restore in operations runbook.

---

### 2.2 Config (`config.yaml`, optional `api_keys.yaml`)

| Aspect | Rollout | Rollback |
|--------|---------|----------|
| **What** | Add new config sections (phase0_prescan, phase5_threat_intel, …, api_server, notifications). All new keys optional with defaults. Keep every existing key and section. | Remove or comment out new sections. Old code never reads them; reverted code stops reading them. |
| **Verification** | Load config with old and new code; no KeyError for existing keys. New phases read new sections when present. | Config without new sections still loads; CLI and phases 1–4 unchanged. |
| **Risk** | Typo in key name could break new features only; existing behaviour unaffected. | None for rollback. |

---

### 2.3 Intelligence Layer (`intelligence/`)

| Aspect | Rollout | Rollback |
|--------|---------|----------|
| **What** | New package `intelligence/` with subpackages (risk_scoring, change_detection, compliance, graph, threat_intel). No changes to technieum.py or modules 01–04. | Remove or don’t deploy `intelligence/`; remove or don’t run new bash phases (05–09) and Phase 0. |
| **Verification** | Unit tests for each module; bash can call `python3 -m intelligence.risk_scoring.calculate ...` with fixture JSON. | Phases 1–4 and technieum.py default behaviour unchanged; new phases simply not invoked. |
| **Risk** | New code could import something from core (e.g. db); keep intelligence/ as independently testable. | None for existing flows. |

---

### 2.4 New Bash Phases (00_prescan.sh, 05–09)

| Aspect | Rollout | Rollback |
|--------|---------|----------|
| **What** | Add new scripts under `modules/`. Orchestrator extended to support phases 0, 5–9 only when user passes e.g. `-p 0,1,2,3,4,5,6,7,8,9`. Default remains `-p 1,2,3,4`. | Do not pass new phase numbers; or remove new scripts and revert orchestrator phase dispatch. Existing 01–04 unchanged. |
| **Verification** | `technieum.py -t example.com -p 1,2,3,4` and `technieum.py -t example.com -p 1,2,3,4 --test` behave as before. New phases run only when explicitly requested. | Same as rollout verification for default and 1–4 only. |
| **Risk** | New script could overwrite or conflict with phase1–4 output paths; design new phases to use distinct dirs (e.g. phase5_threat_intel/, phase7_change_detection/). | Low. |

---

### 2.5 Orchestrator (`technieum.py`)

| Aspect | Rollout | Rollback |
|--------|---------|----------|
| **What** | Extend with: phase 0, 5–9 dispatch; parse_phase0_output … parse_phase9_output; new flags (e.g. --continuous, --api-server). Preserve all existing args and defaults. | Revert technieum.py to previous version; or keep code but don’t use new flags/phases. |
| **Verification** | Compatibility tests: same CLI invocations and (with --test) same outputs. New flags only affect behaviour when used. | Revert commit; compatibility tests pass again. |
| **Risk** | Bug in new branch (e.g. phase 5) could affect only that phase if isolation is kept; ensure no shared state that breaks 1–4. | Low if changes are additive. |

---

### 2.6 Parsers (`parsers/parser.py`)

| Aspect | Rollout | Rollback |
|--------|---------|----------|
| **What** | Add new parser classes (e.g. TechnologyParser, ThreatIntelParser). Existing parsers and URL_TOOL_PARSERS unchanged. New parse_phase*_output methods in technieum.py use new parsers only for new phase outputs. | Revert parser additions and corresponding parse_phase*_output wiring. |
| **Verification** | Existing parser tests and integration tests (phases 1–4) pass. New parser tests for new file formats. | Revert; all parser tests for 1–4 still pass. |
| **Risk** | Accidentally changing an existing parser signature or output format. Mitigation: compatibility tests and unit tests for existing parsers. | Low. |

---

### 2.7 Query CLI (`query.py`)

| Aspect | Rollout | Rollback |
|--------|---------|----------|
| **What** | Move query.py from docs/ to repo root (or symlink). Optionally add new export types or flags (e.g. --risk, --compliance). Preserve all existing flags and output formats. | Move query.py back to docs/ if needed; or revert new flags only. |
| **Verification** | All documented query.py invocations (--list, --summary, --subdomains, --vulns, --export, etc.) produce same behaviour and format. | Same. |
| **Risk** | SQL injection in export (see CODE_AUDIT_REFACTORING_SPEC): ensure table whitelist and parameterized queries. | N/A. |

---

### 2.8 API Layer (`api/`)

| Aspect | Rollout | Rollback |
|--------|---------|----------|
| **What** | Deploy FastAPI app as separate process (or optional in-process with --api-server). API reads/writes same DB. Not required for CLI. | Stop API process; do not start --api-server. CLI and DB unchanged. |
| **Verification** | API health check; list scans, assets, findings via API. CLI-only usage still works without API. | API process stopped; no impact on technieum.py or query.py. |
| **Risk** | API could impose load on DB; use connection pooling and timeouts. Auth: ensure API keys not logged. | None for CLI users. |

---

### 2.9 Web UI (`web/`)

| Aspect | Rollout | Rollback |
|--------|---------|----------|
| **What** | Serve static web/ from API or separate server. Optional. | Stop serving web/ or remove static files. API can remain. |
| **Verification** | Dashboard and scan viewer load; data comes from API. | Disable static route or remove assets. |
| **Risk** | CORS and auth if API is on different origin; configure appropriately. | Low. |

---

### 2.10 Notifications (`notifications/`)

| Aspect | Rollout | Rollback |
|--------|---------|----------|
| **What** | Enable in config (notifications.enabled: true) and configure channels. Orchestrator or monitor calls notification modules on events. | Set notifications.enabled: false or remove config; or revert notification calls. |
| **Verification** | Test webhook or test channel receives alert when triggered. | Alerts stop; no other impact. |
| **Risk** | Misconfiguration could leak data to wrong channel; validate config and use allowlists. | Low. |

---

### 2.11 Reporting (`reporting/`)

| Aspect | Rollout | Rollback |
|--------|---------|----------|
| **What** | New report.py CLI and reporting package; optional dependency. | Don’t install reporting deps; or revert report.py. query.py export remains. |
| **Verification** | report.py generates PDF/HTML for a target; query.py export still works. | Remove or don’t call report.py. |
| **Risk** | Heavy dependencies (e.g. WeasyPrint); optional install. | Low. |

---

### 2.12 Deployment Assets (Docker, systemd, K8s)

| Aspect | Rollout | Rollback |
|--------|---------|----------|
| **What** | Add Dockerfiles, docker-compose, systemd units, scripts (backup, restore, migrate_db). Document in INSTALLATION.md. | Use previous deployment method; new assets are optional. |
| **Verification** | docker-compose up brings up services as documented; migration script runs. | Continue using existing install/setup method. |
| **Risk** | Image or service config errors; test in staging first. | Low. |

---

## 3. Rollout Order (Recommended)

1. **Foundation:** Migrations framework, compatibility tests, query.py at root (Phase A).
2. **DB + Config:** Run migrations, extend config (Phase B).
3. **Intelligence:** Deploy intelligence/ and tests (Phase C).
4. **New phases + orchestrator:** New bash modules and technieum.py extensions (Phase D).
5. **Parsers + wiring:** New parsers and parse_phase* wiring (Phase E).
6. **API + Web:** Deploy API and static UI (Phase F).
7. **Notifications, reporting, CLIs, deployment:** (Phase G).

Each step can be validated and rolled back independently as in the table above.

---

## 4. Rollback Checklist (High Level)

- **DB:** Restore from backup; or run down-migrations if available.
- **Code:** Revert commits for the subsystem (or disable feature flag).
- **Config:** Remove or comment new sections.
- **Processes:** Stop new services (API, monitor, workers).
- **Verification:** Run compatibility test suite and smoke tests.

---

## 5. Dependency Impact Matrix (Summary)

Included in full in [ENTERPRISE_ROADMAP.md](ENTERPRISE_ROADMAP.md#5-dependency-impact-matrix). Summary:

- **Required:** Existing Python deps (pyyaml, dotenv, colorama, tqdm, tabulate, lxml); SQLite.
- **Optional (API):** fastapi, uvicorn, pydantic.
- **Optional (intel/risk):** requests/httpx, networkx.
- **Optional (reporting):** reportlab or similar.
- **Optional (scheduler):** apscheduler.
- **Optional (cache/state):** Redis; fallback SQLite.

New Python packages and external tools (e.g. NVD, Shodan) are documented in ENTERPRISE_ROADMAP and in .env.example with “optional” and rate-limit/TOS notes.

---

## 6. References

- [ENTERPRISE_ROADMAP.md](ENTERPRISE_ROADMAP.md) — Phases, milestones, risks, test strategy.
- [ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md) — ADRs.
- [complete_plan.md](../complete_plan.md) — Detailed feature and directory layout.
