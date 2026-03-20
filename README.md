# Technieum — Attack Surface Management Framework

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue.svg" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-red.svg" alt="Linux">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/Tools-50%2B-orange.svg" alt="50+ Tools">
</p>

Technieum is a comprehensive, database-driven Attack Surface Management (ASM) framework. It orchestrates **50+ reconnaissance and vulnerability assessment tools** across 4 phases to give you complete visibility into any target's external attack surface. Results are stored in SQLite, queryable via a REST API, and viewable in a built-in web dashboard.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [API Keys](#api-keys)
- [Configuration](#configuration)
- [Usage](#usage)
- [Scan Phases](#scan-phases)
- [Web UI & API Server](#web-ui--api-server)
- [Output Structure](#output-structure)
- [Running Tests](#running-tests)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Features

- **4-Phase Scanning Pipeline** — Discovery → Intelligence → Content → Vulnerability
- **50+ Tool Orchestration** — subfinder, amass, nuclei, nmap, httpx, ffuf, and more
- **Database-Driven** — SQLite with WAL mode; 24 relational models tracking every asset
- **Resume Capability** — interrupted scans pick up where they left off
- **Threat Intelligence** — integrates Shodan, Censys, VirusTotal, GreyNoise, AbuseIPDB, OTX, and more
- **Risk Scoring** — CVSS-based scoring with custom weighting and graph-based propagation
- **Change Detection** — tracks asset changes across scans and generates alerts
- **REST API** — FastAPI backend with JWT/API-key auth, rate limiting, and SSE streaming
- **Web Dashboard** — real-time scan monitoring, findings explorer, asset graph visualiser
- **Multi-Target** — run concurrent scans with configurable thread counts

---

## Architecture

```
kali-linux-asm/
├── technieum.py                  # Main entry point — orchestrates all phases
├── config.yaml                # Global settings (targets, threads, timeouts)
├── requirements.txt           # Python dependencies
├── install.sh                 # Full system installer (Go tools, wordlists, venv)
├── setup.sh                   # Quick environment check / post-install verify
│
├── modules/                   # Bash scan modules (one per phase)
│   ├── 01_discovery.sh        # Phase 1 — subdomain + DNS + HTTP enumeration
│   ├── 02_intel.sh            # Phase 2 — Shodan, Censys, GitHub, WHOIS, geoloc
│   ├── 03_content.sh          # Phase 3 — dirs, JS secrets, S3, Wayback, tech stack
│   └── 04_vuln.sh             # Phase 4 — nuclei, SQLi, XSS, CVE scanning
│
├── parsers/
│   └── parser.py              # Output parsers for all 50+ tools
│
├── db/
│   └── database.py            # DatabaseManager — SQLite WAL, singleton pattern
│
├── backend/                   # FastAPI REST API
│   ├── api/
│   │   ├── server.py          # App factory, middleware stack, router registration
│   │   ├── middleware/        # Auth, rate-limit, CSRF, logging
│   │   ├── models/            # Pydantic request/response schemas
│   │   └── routes/            # scans, findings, assets, intel, reports, webhooks
│   ├── db/
│   │   ├── base.py            # SQLAlchemy declarative Base
│   │   ├── models.py          # 24 ORM models
│   │   └── database.py        # Session factory + get_db dependency
│   ├── config.py              # Environment-based settings (pydantic)
│   └── tests/                 # Pytest suite — 131 tests (93 DB + 38 API)
│
├── intelligence/              # Python intelligence engine
│   ├── risk_scoring/          # CVSS scoring engine
│   ├── graph/                 # NetworkX attack-path analysis
│   ├── change_detection/      # Alert generation for asset changes
│   └── threat_intel/          # Multi-source threat intel aggregation
│
└── web/
    └── static/                # Single-page dashboard (vanilla JS + Chart.js)
        ├── index.html
        ├── findings_v2.html
        ├── scan_viewer_v2.html
        └── graph_viewer_v2.html
```

---

## Requirements

### System

| Requirement | Version | Notes |
|-------------|---------|-------|
| Linux | Any modern distro | Tested on Kali 2024.x, Ubuntu 22.04+, Debian 12+ |
| Python | 3.11+ | Must be ≥3.11 for `tomllib`, `ExceptionGroup` |
| Go | 1.22+ | Installed automatically by `install.sh` |
| SQLite | 3.35+ | Usually pre-installed |
| RAM | 2 GB+ | 4 GB recommended for full scans |
| Disk | 5 GB+ | For wordlists and tool binaries |

### Python packages

All Python dependencies are listed in `requirements.txt` and installed into a virtual environment at `.venv/`. Key packages:

| Package | Purpose |
|---------|---------|
| `fastapi` + `uvicorn` | REST API server |
| `sqlalchemy` | ORM / database layer |
| `pydantic` | Data validation |
| `aiohttp` + `httpx` | Async HTTP clients |
| `networkx` | Graph-based attack path analysis |
| `python-jose` | JWT token handling |
| `dnspython` | DNS resolution |
| `nuclei`, `subfinder`, etc. | Installed as Go binaries by `install.sh` |

---

## Installation

### Automated (recommended)

Run the installer as root. It installs system packages, Go, all Go-based recon tools, and creates the Python virtual environment.

```bash
# Clone the repository
git clone https://github.com/your-org/kali-linux-asm.git
cd kali-linux-asm

# Full install (requires internet access, ~10-20 min)
sudo bash install.sh

# Optional flags:
#   --python-only     Skip Go tool installs (Python venv only)
#   --skip-wordlists  Skip SecLists wordlist download
sudo bash install.sh --skip-wordlists
```

### Activate the virtual environment

After install, activate the venv before running any Python commands:

```bash
source .venv/bin/activate
```

To make Go tools available (if not already on PATH):

```bash
export PATH="$PATH:$HOME/go/bin"
```

Add this to `~/.bashrc` to make it permanent:

```bash
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
source ~/.bashrc
```

### Quick environment check

After `install.sh` completes, run the quick-setup verifier:

```bash
bash setup.sh
```

This checks Python packages, critical tools, the database connection, and prints next steps.

### Manual install (no internet on target machine)

```bash
# 1. Create and activate venv
python3 -m venv .venv
source .venv/bin/activate

# 2. Install Python packages
pip install --upgrade pip
pip install -r requirements.txt

# 3. Create directories
mkdir -p output logs

# 4. Copy and edit environment file
cp .env.example .env
nano .env    # Add your API keys
```

---

## API Keys

Technieum integrates with multiple external threat-intelligence APIs. Each key is optional — phases run with reduced coverage if a key is missing. Add keys to `.env` (never commit this file).

### Setup

```bash
# Copy the template
cp .env.example .env

# Edit with your preferred editor
nano .env
```

### Full API key reference

| Variable | Service | Required for | Get it at |
|----------|---------|-------------|-----------|
| `SHODAN_API_KEY` | Shodan | Phase 2 — host/port/banner lookups | https://account.shodan.io |
| `CENSYS_API_ID` | Censys | Phase 2 — certificate + host search | https://search.censys.io/account/api |
| `CENSYS_API_SECRET` | Censys | Phase 2 — (same account as ID) | https://search.censys.io/account/api |
| `SECURITYTRAILS_API_KEY` | SecurityTrails | Phase 1 — historical DNS / subdomains | https://securitytrails.com/app/account/credentials |
| `VT_API_KEY` | VirusTotal | Phase 1 & 4 — URL/file reputation | https://www.virustotal.com/gui/my-apikey |
| `GITHUB_TOKEN` | GitHub | Phase 2 — secret / code leak search | https://github.com/settings/tokens (scope: `public_repo`) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | Threat intel — IP reputation | https://www.abuseipdb.com/account/api |
| `GREYNOISE_API_KEY` | GreyNoise | Threat intel — noise/mass-scanner IPs | https://viz.greynoise.io/account/your-api-key |
| `OTX_API_KEY` | AlienVault OTX | Threat intel — IoC feeds | https://otx.alienvault.com/api |
| `HIBP_API_KEY` | Have I Been Pwned | Phase 2 — data-breach email check | https://haveibeenpwned.com/API/Key |
| `EMAILREP_API_KEY` | EmailRep.io | Threat intel — email reputation | https://emailrep.io/key |
| `URLSCAN_API_KEY` | URLScan.io | Phase 3 — page screenshot/analysis | https://urlscan.io/user/profile/ |
| `PULSEDIVE_API_KEY` | Pulsedive | Threat intel — enrichment | https://pulsedive.com/dashboard/?key |
| `BINARYEDGE_API_KEY` | BinaryEdge | Phase 2 — internet-wide scan data | https://app.binaryedge.io/account/api |
| `CROWDSEC_API_KEY` | CrowdSec | Threat intel — community blocklist | https://app.crowdsec.net/settings/api-keys |
| `GSB_API_KEY` | Google Safe Browsing | Phase 4 — URL safety check | https://developers.google.com/safe-browsing/v4/get-started |
| `WPSCAN_API_TOKEN` | WPScan | Phase 4 — WordPress CVE DB | https://wpscan.com/profile |
| `PASTEBIN_API_KEY` | Pastebin | Phase 3 — paste monitoring | https://pastebin.com/api |
| `NVD_API_KEY` | NVD (NIST) | Phase 4 — CVE lookups (rate-limit bypass) | https://nvd.nist.gov/developers/request-an-api-key |
| `DEHASHED_API_KEY` | DeHashed | Threat intel — credential leaks | https://www.dehashed.com/profile |
| `DEHASHED_EMAIL` | DeHashed | Threat intel — account email | (same account) |

> **Free tiers are sufficient** for most keys. The tool degrades gracefully when keys are absent — it skips that specific lookup and logs a warning.

### Minimum viable key set

For a functional scan with good coverage, you need at minimum:

```bash
SHODAN_API_KEY=...
SECURITYTRAILS_API_KEY=...
VT_API_KEY=...
GITHUB_TOKEN=...
```

---

## Configuration

Main configuration lives in `config.yaml`. Override any setting without editing the file by setting the corresponding environment variable.

```yaml
# config.yaml — key settings

general:
  output_dir: "output"      # Where raw tool output is written
  database: "technieum.db"     # SQLite database file
  threads: 5                # Concurrent scan workers
  timeout: 3600             # Per-phase timeout (seconds)

phase1_discovery:
  enabled: true
  subdomain_tools:          # Tools used in order; first found = used
    - subfinder
    - amass
    - assetfinder
    - securitytrails        # Requires SECURITYTRAILS_API_KEY

phase2_intel:
  enabled: true

phase3_content:
  enabled: true
  wordlists:
    directories: "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"

phase4_vuln:
  enabled: true
  nuclei:
    severity: ["critical", "high", "medium"]
    templates: "/root/nuclei-templates"
```

---

## Usage

### Basic scan

```bash
# Activate venv first
source .venv/bin/activate

# Run all 4 phases against a target domain
python3 technieum.py -t example.com

# Specify output directory
python3 technieum.py -t example.com -o /tmp/example-scan

# Run with more threads
python3 technieum.py -t example.com --threads 10
```

### Phase selection

```bash
# Run only Phase 1 (subdomain discovery)
python3 technieum.py -t example.com --phase 1

# Run only Phase 4 (vulnerability scanning)
python3 technieum.py -t example.com --phase 4

# Run phases 1 and 2 only
python3 technieum.py -t example.com --phases 1,2
```

### Resume an interrupted scan

```bash
# Resume using the existing database
python3 technieum.py -t example.com --resume
```

### Multiple targets

```bash
# From a file (one domain per line)
python3 technieum.py --targets-file targets.txt

# Comma-separated inline
python3 technieum.py -t "example.com,corp.example.com"
```

### Query results

```bash
# Interactive query tool
python3 query.py

# Show all subdomains found
python3 query.py --target example.com --show subdomains

# Show all critical/high vulnerabilities
python3 query.py --target example.com --show vulns --severity critical,high

# Export to JSON
python3 query.py --target example.com --export json > results.json
```

### Full CLI reference

```
python3 technieum.py --help

usage: technieum.py [-h] [-t TARGET] [--targets-file FILE] [-o OUTPUT]
                 [--phase PHASE] [--phases PHASES] [--threads N]
                 [--timeout SEC] [--resume] [--dry-run] [-v]

  -t, --target        Target domain (e.g. example.com)
  --targets-file      File with one domain per line
  -o, --output        Output directory (default: output/<target>)
  --phase             Run a single phase (1-4)
  --phases            Comma-separated phases to run (e.g. 1,3)
  --threads           Concurrent workers (default: 5)
  --timeout           Per-phase timeout in seconds (default: 3600)
  --resume            Resume an interrupted scan
  --dry-run           Print what would run, execute nothing
  -v, --verbose       Enable debug logging
```

---

## Scan Phases

### Phase 1 — Discovery & Enumeration

Enumerates subdomains, resolves DNS, validates live hosts, and checks HTTP/HTTPS.

**Tools used:** `subfinder`, `amass`, `assetfinder`, `subdominator`, `crt.sh`, `SecurityTrails`, `dnsx`, `httpx`, `massdns`

**What it finds:**
- All subdomains (live and dead)
- A/AAAA/CNAME/MX/TXT/NS records
- HTTP status codes, titles, server headers
- Open redirects, HTTPS mismatches
- CDN / WAF detection

**Output:** `output/<target>/phase1/`

---

### Phase 2 — Intelligence & Infrastructure

Maps infrastructure using OSINT and threat intelligence APIs.

**Tools used:** `shodan`, `censys`, `binaryedge`, `nmap`, `masscan`, `whois`, `GitHub dork search`, `gau`, `waybackurls`

**What it finds:**
- Open ports and running services (banner-level)
- SSL/TLS certificates (expiry, SANs, issuers)
- Cloud provider / ASN / geolocation
- GitHub secret leaks tied to the domain
- Historical URLs from Wayback Machine
- Data breach exposure (HIBP)

**Output:** `output/<target>/phase2/`

---

### Phase 3 — Deep Web & Content Discovery

Discovers hidden content, exposed credentials, and technology stack details.

**Tools used:** `ffuf`, `gobuster`, `feroxbuster`, `gitleaks`, `truffleHog`, `nuclei` (exposure templates), `S3Scanner`, `Pastebin monitor`, `whatweb`, `wappalyzer`

**What it finds:**
- Hidden directories and sensitive files (`.env`, `backup.zip`, `phpinfo.php`, etc.)
- Hardcoded secrets in JavaScript files
- Exposed S3 buckets and Azure blobs
- Paste site mentions
- Technology fingerprints (CMS, frameworks, libraries)
- Subdomain takeover candidates

**Output:** `output/<target>/phase3/`

---

### Phase 4 — Vulnerability Scanning

Runs targeted vulnerability checks using nuclei templates and specialised scanners.

**Tools used:** `nuclei`, `nikto`, `sqlmap`, `dalfox`, `wpscan`, `testssl.sh`, `nmap` (vuln scripts), `VirusTotal`, `Google Safe Browsing`

**What it finds:**
- CVE-mapped vulnerabilities (CVSS scored)
- SQL injection, XSS, SSRF, SSTI, open redirect
- WordPress / Joomla / Drupal plugin CVEs
- SSL/TLS weaknesses (BEAST, POODLE, expired certs)
- HTTP security header misconfigurations
- Default credentials on exposed admin panels

**Output:** `output/<target>/phase4/`, risk scores stored in DB

---

## Web UI & API Server

### Start the API server

```bash
source .venv/bin/activate

# Start with default settings (port 8000)
python3 -m uvicorn backend.api.server:app --host 0.0.0.0 --port 8000

# With auto-reload (development)
python3 -m uvicorn backend.api.server:app --reload --port 8000
```

### Access the dashboard

Open in your browser:

```
http://localhost:8000/
```

Available pages:

| URL | Page |
|-----|------|
| `/` | Main dashboard — scan status, top findings |
| `/findings_v2.html` | Findings explorer — filter by severity, type, status |
| `/scan_viewer_v2.html` | Live scan monitor with SSE progress |
| `/graph_viewer_v2.html` | Attack-path graph visualiser |

### API authentication

All API endpoints (except `/health` and `/version`) require an API key.

**Create an API key** (first run — connect directly to the database):

```bash
source .venv/bin/activate
python3 - <<'EOF'
import hashlib, os, sys
sys.path.insert(0, '.')
os.environ.setdefault("DATABASE_URL", "sqlite:///./technieum.db")

from backend.db.database import SessionLocal
from backend.db.models import APIToken
from datetime import datetime, timedelta

key = os.urandom(32).hex()  # 64-char hex key
key_hash = hashlib.sha256(key.encode()).hexdigest()

db = SessionLocal()
token = APIToken(
    token_hash=key_hash,
    user_name="admin",
    token_type="bearer",
    is_active=True,
    expires_at=datetime.utcnow() + timedelta(days=365),
)
db.add(token)
db.commit()
db.close()

print(f"\nYour API key (save this — it won't be shown again):\n\n  {key}\n")
EOF
```

**Use the key in requests:**

```bash
# Header-based (recommended)
curl -H "X-API-Key: <your-key>" http://localhost:8000/api/v1/scans/

# Bearer token
curl -H "Authorization: Bearer <your-key>" http://localhost:8000/api/v1/scans/
```

### Key API endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check (no auth) |
| `GET` | `/api/v1/scans/` | List scans (paginated) |
| `POST` | `/api/v1/scans/` | Create a new scan |
| `GET` | `/api/v1/scans/{id}` | Get scan details |
| `POST` | `/api/v1/scans/{id}/start` | Start a scan |
| `POST` | `/api/v1/scans/{id}/stop` | Stop a running scan |
| `GET` | `/api/v1/scans/{id}/progress` | Get scan progress |
| `GET` | `/api/v1/findings/` | List findings (paginated, filterable) |
| `GET` | `/api/v1/findings/by-severity` | Findings grouped by severity |
| `PATCH` | `/api/v1/findings/{id}` | Update a finding |
| `GET` | `/api/v1/assets/` | List discovered assets |
| `GET` | `/api/v1/assets/search` | Search assets by keyword |
| `GET` | `/api/v1/intel/threat-feed` | Threat intelligence feed |
| `GET` | `/api/v1/reports/` | List generated reports |
| `POST` | `/api/v1/reports/` | Generate a new report |
| `GET` | `/api/v1/webhooks/` | List webhooks |
| `POST` | `/api/v1/webhooks/` | Register a webhook |

Full interactive API docs: `http://localhost:8000/docs`

---

## Output Structure

```
output/
└── example.com/
    ├── phase1/
    │   ├── subdomains.txt          # All discovered subdomains
    │   ├── dns_records.json        # A, AAAA, CNAME, MX, TXT records
    │   ├── live_hosts.txt          # HTTP/HTTPS validated hosts
    │   └── httpx_results.json      # Full httpx output
    ├── phase2/
    │   ├── shodan_results.json
    │   ├── censys_results.json
    │   ├── ports.txt               # Open ports per host
    │   ├── ssl_certs.json
    │   └── github_leaks.txt
    ├── phase3/
    │   ├── directories.txt         # ffuf/gobuster hits
    │   ├── js_secrets.txt          # Secrets found in JS files
    │   ├── s3_buckets.txt
    │   └── technologies.json
    └── phase4/
        ├── nuclei_results.json     # Full nuclei output (CVSS scored)
        ├── sqlmap_results/
        ├── ssl_issues.txt
        └── summary.json            # Phase summary with risk score
```

All findings are also written to `technieum.db` for querying and API access.

---

## Running Tests

```bash
source .venv/bin/activate

# All tests (93 DB model tests + 38 API endpoint tests)
pytest backend/tests/ -v

# With coverage report
pytest backend/tests/ --cov=backend --cov-report=term-missing

# Intelligence module tests
pytest intelligence/tests/ -v

# Specific test file
pytest backend/tests/test_api.py -v --tb=short

# Quick smoke test
pytest backend/tests/ -x -q
```

Expected output: `131 passed` (93 DB + 38 API).

---

## Troubleshooting

### `externally-managed-environment` error (Kali / Debian 12+)

Kali Linux enforces PEP 668 and blocks system-wide pip installs. Use the venv:

```bash
# install.sh creates .venv automatically; just activate it
source .venv/bin/activate
pip install -r requirements.txt
```

If you need to bypass for a quick test (not recommended):

```bash
pip install --break-system-packages -r requirements.txt
```

### Go tools not found after install

```bash
# Ensure Go bin directory is on PATH
export PATH="$PATH:$HOME/go/bin"
which subfinder   # should print /root/go/bin/subfinder

# Persist in shell config
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
source ~/.bashrc
```

### Database errors / tables missing

```bash
# Recreate the database schema
source .venv/bin/activate
python3 -c "
import os; os.environ['DATABASE_URL'] = 'sqlite:///./technieum.db'
from backend.db.base import Base
from backend.db.database import engine
import backend.db.models   # registers all models
Base.metadata.create_all(bind=engine)
print('Schema created.')
"
```

### API server won't start — port already in use

```bash
# Check what's using port 8000
ss -tlnp | grep 8000
# or
lsof -i :8000

# Use a different port
python3 -m uvicorn backend.api.server:app --port 8080
```

### Nuclei templates out of date

```bash
nuclei -update-templates
```

### Permission denied on scan modules

```bash
chmod +x modules/*.sh
```

### Rate-limited by threat intelligence APIs

The tool automatically backs off on HTTP 429 responses. If you hit limits frequently:
- Upgrade your API plan, or
- Set `threads: 2` in `config.yaml` to reduce concurrency, or
- Run phases separately with a delay between them

### SQLite WAL lock issues (concurrent access)

If you see `database is locked` errors when the API server and scanner run simultaneously, set the WAL journal mode explicitly:

```bash
sqlite3 technieum.db "PRAGMA journal_mode=WAL;"
```

---

## .env Reference

The installer creates a `.env` file with placeholder values. Fill in your actual API keys:

```bash
# ──────────────────────────────────────────────────────────────────
# Technieum Environment Configuration
# ──────────────────────────────────────────────────────────────────

# Database (default: SQLite in project root)
DATABASE_URL=sqlite:///./technieum.db

# API server secret (generate with: openssl rand -hex 32)
SECRET_KEY=change_me_generate_with_openssl_rand_hex_32

# ── Phase 1 ──────────────────────────────────────────────────────
SECURITYTRAILS_API_KEY=your_key_here
VT_API_KEY=your_key_here

# ── Phase 2 ──────────────────────────────────────────────────────
SHODAN_API_KEY=your_key_here
CENSYS_API_ID=your_key_here
CENSYS_API_SECRET=your_key_here
GITHUB_TOKEN=ghp_your_token_here

# ── Phase 3 / Content ────────────────────────────────────────────
PASTEBIN_API_KEY=your_key_here
WPSCAN_API_TOKEN=your_key_here

# ── Phase 4 / Vulnerability ──────────────────────────────────────
GSB_API_KEY=your_key_here
NVD_API_KEY=your_key_here

# ── Threat Intelligence ──────────────────────────────────────────
HIBP_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
GREYNOISE_API_KEY=your_key_here
OTX_API_KEY=your_key_here
EMAILREP_API_KEY=your_key_here
URLSCAN_API_KEY=your_key_here
PULSEDIVE_API_KEY=your_key_here
BINARYEDGE_API_KEY=your_key_here
CROWDSEC_API_KEY=your_key_here
DEHASHED_API_KEY=your_key_here
DEHASHED_EMAIL=your_email_here
```

Generate `SECRET_KEY`:

```bash
openssl rand -hex 32
```

---

## License

MIT — see [LICENSE](LICENSE) for details.

This tool is intended for **authorised security assessments only**. Always obtain written permission before scanning any system you do not own.
