# Architecture Decision Records (ADR)

This document records architecture decisions for the Technieum → Enterprise ASM evolution in ADR style. Each entry is immutable once accepted; new decisions get new ADRs.

---

## ADR-001: Incremental, Non-Breaking Migration

**Status:** Accepted  
**Context:** Technieum is in production use with a known CLI, four bash phases, and SQLite. A full rewrite would break users and scripts.  
**Decision:** Evolve the codebase incrementally. No breaking changes to existing CLI flags, output paths, or default behaviour. New features are additive and opt-in (e.g. new phases via `-p 0,5,6,7,8,9`).  
**Consequences:** Some technical debt remains; new code must respect compatibility tests. Rollback is straightforward by not running new phases or new binaries.

---

## ADR-002: SQLite as Default Runtime Database

**Status:** Accepted  
**Context:** Current implementation uses SQLite with WAL mode. Enterprise ASM could use PostgreSQL or other DBs.  
**Decision:** SQLite remains the default and fully supported runtime database. No mandatory external database for core or API. Optional support for other backends may be added later behind an abstraction layer.  
**Consequences:** Single-file DB simplifies deployment and backup. Scale limits (concurrent writes, size) are acceptable for typical single-team or single-tenant usage. API and CLI share the same DB file.

---

## ADR-003: Bash Phase Scripts Remain Primary Executors for Scanning

**Status:** Accepted  
**Context:** Scanning is implemented as bash scripts (01–04) that invoke many external tools (Nmap, Nuclei, etc.). Moving everything to Python would be a large rewrite and could break tool chains.  
**Decision:** Keep bash as the primary executor for scan phases. New phases (0, 5–9) are also bash scripts that may call Python modules for complex logic. The orchestrator (technieum.py) invokes scripts with `(target, output_dir)` and parses outputs in Python.  
**Consequences:** Consistency with existing design; easy to add new tools in bash. Python is used for parsing, DB, risk/compliance/graph logic, and API. Cross-platform is limited to Unix-like environments where bash and tools exist.

---

## ADR-004: Parser Layer in Python; Single parser.py Extended Additively

**Context:** All tool outputs are currently parsed in `parsers/parser.py` (SubdomainParser, HttpParser, PortParser, etc.). New phases and tools require new parsers.  
**Decision:** Keep a single parser module (or package) and extend it additively with new parser classes (e.g. TechnologyParser, ThreatIntelParser, ComplianceParser). Existing parser interfaces and expected file paths are not changed.  
**Consequences:** Parsers stay in one place; risk of large file is mitigated by clear class boundaries. New parsers must follow the same patterns (read file → return list of dicts) for consistency with DB bulk inserts.

---

## ADR-005: Schema Evolution via Migrations Only

**Status:** Accepted  
**Context:** New tables (service_inventory, threat_intelligence, scan_baselines, etc.) are needed. Changing `database.py` inline would make upgrades and rollbacks hard.  
**Decision:** Introduce a `db/migrations/` directory. Schema changes are applied via versioned migration scripts (SQL or Python). A version/schema table records applied migration version. New installs can run full schema + migrations; existing installs run only new migrations.  
**Consequences:** Additive migrations only for compatibility; no in-place column renames or drops on existing tables. Rollback procedure is “restore DB backup and revert code” or “run down-migration” if we add down scripts.

---

## ADR-006: API as Separate Process; Same DB as CLI

**Status:** Accepted  
**Context:** Enterprise ASM requires an API for UI and integrations. Tight coupling would complicate CLI-only deployments.  
**Decision:** The API (FastAPI) runs as a separate process. It reads and writes the same SQLite (or configured) database as the CLI. No requirement to run the API for CLI usage. Orchestrator may support an `--api-server` flag that starts the API in-process for convenience, but the primary deployment is “API server optional.”  
**Consequences:** Single source of truth (DB); operators can run CLI-only or API+web. No duplicate data stores.

---

## ADR-007: Static Web UI + Lightweight Server

**Status:** Accepted  
**Context:** A real-time web UI is desired (dashboard, scan viewer, findings, graph).  
**Decision:** Implement `web/` as static assets (HTML/CSS/JS). Serve via the same FastAPI app (static mount) or a minimal separate server. No mandatory server-side rendering; API provides data (REST + optional SSE for logs).  
**Consequences:** Simple deployment; front-end can be developed independently. Real-time updates via polling or SSE to API.

---

## ADR-008: Intelligence Logic in Python Packages Invokable from Bash

**Status:** Accepted  
**Context:** Phases 5–9 need non-trivial logic (risk scoring, delta calculation, compliance mapping, graph building). Bash alone would be hard to maintain.  
**Decision:** Implement this logic in Python under `intelligence/` (e.g. `risk_scoring`, `change_detection`, `compliance`, `graph`, `threat_intel`). Each module is callable as a CLI (e.g. `python3 -m intelligence.risk_scoring.calculate --findings ... --output ...`) with JSON (or file) input/output so bash can invoke it. Same code is importable from API or orchestrator.  
**Consequences:** Clear contract: JSON in, JSON out, exit 0/1. Bash remains the phase driver; Python does the heavy lifting. Testability is high.

---

## ADR-009: Configuration in YAML; Secrets in Environment

**Status:** Accepted  
**Context:** config.yaml holds general and phase settings. API keys and secrets should not live in repo or config in plain text.  
**Decision:** Keep `config.yaml` for non-secret configuration. Reference secrets via environment variables (e.g. `${SHODAN_API_KEY}`). Provide `.env.example` and optionally a separate `api_keys.yaml` (gitignored) for local overrides.  
**Consequences:** No secrets in version control; same pattern as current config.yaml API key placeholders.

---

## ADR-010: Existing CLI Entry Points Preserved; New CLIs Alongside

**Status:** Accepted  
**Context:** technieum.py and query.py are the documented entry points. New capabilities (monitor, report, admin) need entry points.  
**Decision:** Preserve `technieum.py` and `query.py` (including all existing flags and output behaviour). Add new scripts alongside: `monitor.py`, `report.py`, `admin.py`. No merging of query.py into technieum.py; keep single responsibility. query.py is placed at repository root (currently under docs/) for consistent CLI usage.  
**Consequences:** Users and scripts that rely on current invocations keep working. New features are discoverable via new commands.

---

## ADR-011: Optional Dependencies for Optional Features

**Status:** Accepted  
**Context:** API, reporting, ML, Redis, etc. are not required for core scanning.  
**Decision:** Core `requirements.txt` stays minimal (current deps). API, reporting, and other optional features use optional dependencies (e.g. `requirements-api.txt` or `pip install .[api]`). Document in INSTALLATION.md.  
**Consequences:** CLI-only installs stay light; full platform install is explicit. Fail gracefully when optional deps are missing (e.g. “install with [api] extra for API server”).

---

## ADR-012: Compatibility Test Suite as Gate

**Status:** Accepted  
**Context:** Regressions in existing behaviour would break users.  
**Decision:** Maintain a dedicated compatibility test suite that asserts: (1) technieum.py with `-t domain -p 1,2,3,4` (and --test) behaviour; (2) query.py flags and export formats; (3) modules 01–04 produce expected output layout. These tests run on every PR and must pass before merging.  
**Consequences:** Safe refactors and new features; explicit “no break” guarantee for documented behaviour.

---

## Index

| ADR    | Title |
|--------|--------|
| 001 | Incremental, Non-Breaking Migration |
| 002 | SQLite as Default Runtime Database |
| 003 | Bash Phase Scripts Remain Primary Executors |
| 004 | Parser Layer Extended Additively |
| 005 | Schema Evolution via Migrations Only |
| 006 | API as Separate Process; Same DB as CLI |
| 007 | Static Web UI + Lightweight Server |
| 008 | Intelligence Logic in Python, Invokable from Bash |
| 009 | Configuration in YAML; Secrets in Environment |
| 010 | Existing CLI Entry Points Preserved |
| 011 | Optional Dependencies for Optional Features |
| 012 | Compatibility Test Suite as Gate |
