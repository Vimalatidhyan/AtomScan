---
name: onboard-technieum
description: Onboard as team lead for Technieum and ensure production readiness. Use when the user wants to understand architecture, fix all errors, and make all functionality ready (UI↔API wiring, worker pipeline, domain models).
---

# Onboard Technieum (Team Lead) — Errors Fixed, Functionality Ready

## Goal
Onboard as team lead for Technieum. **All errors must be fixed and all functionality must be ready.** Identify and fix issues; ensure UI, API, worker pipeline, and data layer work end-to-end with no outstanding bugs or missing behavior.

## Inputs
Core context files in **archive/context/** (read these first):
- **archive/context/ProductDocumentation.txt** — README, architecture, 4-phase pipeline, API keys, config, usage
- **archive/context/SolutionFileStructure.txt** — Full repo file tree (backend, web, modules, parsers, db, intelligence)
- **archive/context/DomainModels.txt** — Pydantic API schemas + SQLAlchemy ORM (25 models: ScanRun, Subdomain, Vulnerability, etc.)
- **archive/context/Services.txt** — API route implementations (metrics, findings, intel, scans, assets, etc.)
- **archive/context/Presentation.txt** — Web UI HTML (dashboard, scan viewer, findings, graph)

Repo map for agents: **AGENT_NAVIGATION.md** at repo root.

## Instructions
1. **Read and summarize** each file: architecture, data model, service surfaces, UI patterns, repository structure.
2. **Produce a mental model**: components, data flow, dependencies, and known gaps.
3. **Identify all errors and missing functionality**: linter/runtime errors, broken API routes, UI↔API mismatches, worker/ingestion failures, DB/schema issues, env/config gaps.
4. **Fix all errors and complete functionality**: resolve every identified error; implement or wire any missing behavior so the system is fully functional (no 2-week phased plan — deliver a ready state).
5. **Verify readiness**: confirm all fixes are applied and no known errors or missing features remain; list any remaining risks or follow-ups.

## Output
- **Executive summary** (2–3 paragraphs): current state and what was fixed or completed.
- **Architecture map** (bulleted).
- **Errors fixed & functionality completed** (checklist with status).
- **Readiness verification**: what was checked and that all targeted errors are fixed and functionality is ready.
- **Remaining risks or follow-ups** (if any), with mitigations.

## Quick reference
- **Technieum**: ASM framework — 4 phases (Discovery → Intel → Content → Vuln), 50+ tools, SQLite, FastAPI, vanilla JS dashboard.
- **Backend**: `backend/` — FastAPI app, `app/db/models.py` (25 ORM models), `app/api/routes/` (findings, scans, intel, metrics, assets).
- **UI**: `web/static/` — index.html (dashboard), scan_viewer_v2.html, findings_v2.html, graph_viewer_v2.html; JS calls `/api/v1/` (e.g. findings, scans).
- **Orchestration**: `technieum.py`, `modules/01_discovery.sh`–`04_vuln.sh`, `parsers/parser.py`, `db/database.py`.
