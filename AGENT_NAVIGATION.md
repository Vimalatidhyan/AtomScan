# Agent navigation — Technieum repo

Use this to navigate the repo. Root is kept minimal; detailed context lives in `archive/`.

## Root (essential)

| Item | Purpose |
|------|---------|
| **README.md** | Project overview, install, usage |
| **PRODUCTION_READINESS.md** | Release readiness and gaps |
| **TRACKER.md** | Current status and checklist |
| **CHANGES.md** | Changelog (production hardening) |
| **config.yaml** | Global and phase config |
| **requirements.txt** | CLI/orchestrator deps |
| **requirements-api.txt** | API + worker deps |
| **technieum.py** | Main CLI orchestrator |
| **query.py** | Result query CLI |
| **start.sh** | Start API + optional worker |
| **install.sh**, **setup.sh** | Environment setup |
| **conftest.py**, **pytest.ini** | Test config |

## Key directories

| Path | Purpose |
|------|---------|
| **app/** | FastAPI app: `api/`, `db/`, workers |
| **backend/** | Legacy backend (if used) |
| **web/static/** | Dashboard and static assets |
| **modules/** | Bash scan phases (01–04) |
| **parsers/** | Output parsers |
| **db/** | DB helpers, migrations |
| **intelligence/** | Risk, graph, change detection, threat intel |
| **tests/** | Pytest + prod_readiness_test.py |
| **docs/** | Architecture, roadmap, ADRs |
| **scripts/** | Utilities |

## Onboarding context (for AI)

Full context for the **onboard-technieum** skill is under **archive/context/**:

- `archive/context/ProductDocumentation.txt` — README, architecture, pipeline
- `archive/context/SolutionFileStructure.txt` — Repo file tree
- `archive/context/DomainModels.txt` — Pydantic + ORM models
- `archive/context/Services.txt` — API route code
- `archive/context/Presentation.txt` — Web UI HTML

See **.cursor/skills/onboard-technieum/SKILL.md** for the full onboarding workflow.

## Archive

| Path | Contents |
|------|----------|
| **archive/context/** | Concatenated context files for agents (see above) |
| **archive/root_docs/** | Old planning, specs, PDFs (not needed for daily navigation) |
| **archive/legacy/** | Legacy code (existing) |
