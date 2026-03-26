# Technieum — Complete Documentation

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue.svg" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-red.svg" alt="Linux">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/Tools-57-orange.svg" alt="57 Tools">
  <img src="https://img.shields.io/badge/API%20Integrations-22-blueviolet.svg" alt="22 APIs">
</p>

> **Technieum** is a comprehensive, database-driven **Attack Surface Management (ASM)** framework that orchestrates **57 reconnaissance and vulnerability assessment tools** across **9 scan modules** to provide complete visibility into any target's external attack surface.

---

## Table of Contents

1. [Overview — How the Tool Works](#1-overview--how-the-tool-works)
2. [Architecture](#2-architecture)
3. [Complete Tool Inventory (57 Tools)](#3-complete-tool-inventory-57-tools)
4. [Complete API Key Reference (22 Keys)](#4-complete-api-key-reference-22-keys)
5. [API Key Pricing & Free Tiers](#5-api-key-pricing--free-tiers)
6. [REST API Reference](#6-rest-api-reference)
7. [Web Dashboard](#7-web-dashboard)
8. [Installation & Setup](#8-installation--setup)
9. [Configuration Reference](#9-configuration-reference)
10. [Usage Guide](#10-usage-guide)
11. [Intelligence Engine](#11-intelligence-engine)
12. [Docker Deployment](#12-docker-deployment)
13. [Troubleshooting](#13-troubleshooting)
14. [License & Legal](#14-license--legal)

---

## 1. Overview — How the Tool Works

Technieum operates as an **automated pipeline** that scans a target domain through multiple phases:

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  PHASE 1    │ ──► │  PHASE 2     │ ──► │  PHASE 3     │ ──► │  PHASE 4     │
│  Discovery  │     │ Intelligence │     │  Content     │     │ Vulnerability│
│  18 tools   │     │  16 tools    │     │  16 tools    │     │  13 tools    │
└─────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
       │                    │                    │                    │
       ▼                    ▼                    ▼                    ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │                    SQLite Database (24 ORM models)               │
   └──────────────────────────────────────────────────────────────────┘
       │                    │                    │                    │
       ▼                    ▼                    ▼                    ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │     Intelligence Engine (Risk Scoring, Attack Graphs,           │
   │     Change Detection, Threat Intel, Compliance)                 │
   └──────────────────────────────────────────────────────────────────┘
       │
       ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │     FastAPI REST API + Web Dashboard (Real-time monitoring)     │
   └──────────────────────────────────────────────────────────────────┘
```

### How a Scan Runs

1. **User provides a target domain** (e.g., `example.com`) via CLI or Web UI
2. **Phase 1 (Discovery):** Enumerates subdomains, resolves DNS, validates live hosts
3. **Phase 2 (Intelligence):** Gathers OSINT data from Shodan, Censys, GitHub, etc.
4. **Phase 3 (Content):** Discovers hidden directories, JS secrets, cloud assets
5. **Phase 4 (Vulnerability):** Runs nuclei, SQLi, XSS, CMS, SSL scans
6. **Extended Modules (5-9):** Threat intel enrichment, CVE correlation, change detection, compliance checks, attack graph generation
7. **All results** are stored in SQLite and accessible via REST API or Web Dashboard
8. **Resume capability** — interrupted scans pick up where they left off

---

## 2. Architecture

```
technieum-x/
├── technieum.py                  # Main entry point — orchestrates all phases
├── config.yaml                   # Global settings (targets, threads, timeouts)
├── requirements.txt              # Python dependencies
├── install.sh                    # Full system installer
├── setup.sh                      # Quick environment check
│
├── modules/                      # Bash scan modules (one per phase)
│   ├── 00_prescan.sh             # Pre-scan checks
│   ├── 01_discovery.sh           # Phase 1 — subdomain + DNS + HTTP
│   ├── 02_intel.sh               # Phase 2 — Shodan, Censys, WHOIS
│   ├── 03_content.sh             # Phase 3 — dirs, JS, S3, Wayback
│   ├── 04_vuln.sh                # Phase 4 — nuclei, SQLi, XSS, CVE
│   ├── 05_threat_intel.sh        # Phase 5 — Threat intelligence feeds
│   ├── 06_cve_correlation.sh     # Phase 6 — CVE correlation
│   ├── 07_change_detection.sh    # Phase 7 — Asset change detection
│   ├── 08_compliance.sh          # Phase 8 — Compliance checks
│   └── 09_attack_graph.sh        # Phase 9 — Attack graph generation
│
├── parsers/
│   └── parser.py                 # Output parsers for all 57 tools
│
├── db/
│   └── database.py               # DatabaseManager — SQLite WAL, singleton
│
├── backend/                      # FastAPI REST API
│   ├── api/
│   │   ├── server.py             # App factory, middleware, routers
│   │   ├── middleware/           # Auth, rate-limit, CSRF, logging
│   │   ├── models/              # Pydantic request/response schemas
│   │   └── routes/              # scans, findings, assets, intel, reports, webhooks, stream
│   ├── db/
│   │   ├── base.py              # SQLAlchemy declarative Base
│   │   ├── models.py            # 24 ORM models
│   │   └── database.py          # Session factory + get_db dependency
│   └── config.py                # Environment-based settings
│
├── intelligence/                 # Python intelligence engine
│   ├── risk_scoring/            # CVSS scoring engine
│   ├── graph/                   # NetworkX attack-path analysis
│   ├── change_detection/        # Alert generation for asset changes
│   ├── threat_intel/            # Multi-source threat intel aggregation
│   └── compliance/              # Compliance checking engine
│
├── web/static/                   # Single-page dashboard (vanilla JS + Chart.js)
│   ├── index.html               # Main dashboard
│   ├── findings_v2.html         # Findings explorer
│   ├── scan_viewer_v2.html      # Live scan monitor
│   └── graph_viewer_v2.html     # Attack-path graph visualiser
│
└── docs/                         # Documentation
```

### Technology Stack

| Component | Technology |
|-----------|-----------|
| **Core Engine** | Python 3.11+ |
| **Scan Modules** | Bash shell scripts |
| **Database** | SQLite with WAL mode (PostgreSQL optional) |
| **ORM** | SQLAlchemy (24 models) |
| **API Backend** | FastAPI + Uvicorn |
| **Authentication** | JWT + API Key (SHA-256 hashed) |
| **Web Dashboard** | Vanilla JS + Chart.js |
| **Graph Engine** | NetworkX |
| **Containerization** | Docker + Docker Compose |
| **Recon Tools** | Go-based CLI tools (57 tools) |

---

## 3. Complete Tool Inventory (57 Tools)

### Phase 1 — Discovery & Enumeration (18 Tools)

| # | Tool | Purpose | Status | API Key Required | Notes |
|---|------|---------|--------|-----------------|-------|
| 1 | **subfinder** | Fast subdomain enumeration | ✅ Working | Optional (improves results) | Primary tool; 50 threads |
| 2 | **assetfinder** | Subdomain finder via various sources | ✅ Working | No | Alternative enumeration |
| 3 | **sublist3r** | Subdomain enumeration via APIs | ✅ Working | No | 20 min timeout |
| 4 | **subdominator** | Subdomain enumeration | ✅ Working | No | 20 min timeout |
| 5 | **ct-monitor** | Certificate Transparency monitoring | ✅ Working | No | Monitors new certs |
| 6 | **crt.sh** | Public certificate database | ✅ Working | No | Built-in HTTPS query |
| 7 | **whois** | WHOIS lookups | ✅ Working | No | 1 min timeout |
| 8 | **securitytrails** | SecurityTrails API integration | ✅ Working | `SECURITYTRAILS_API_KEY` | Historical DNS / subdomains |
| 9 | **certspotter** | Certificate Transparency logs | ✅ Working | No | Alternative CT source |
| 10 | **dnsx** | DNS validator and resolver | ✅ Working | No | 100 threads |
| 11 | **dnsbruter** | DNS brute-force enumeration | ✅ Working | No | 30 min timeout |
| 12 | **dnsprober** | DNS probing tool | ✅ Working | No | Passive subdomains |
| 13 | **httpx** | HTTP server detection | ✅ Working | No | 100 threads; 15s/probe |
| 14 | **asnmap** | ASN/CIDR mapping | ✅ Working | No | Network-level discovery |
| 15 | **mapcidr** | CIDR to IP expansion | ✅ Working | No | 20 min timeout |
| 16 | **cloud_enum** | Cloud bucket enumeration | ✅ Working | No | S3, GCP, Azure |
| 17 | **s3scanner** | AWS S3 bucket finder | ✅ Working | No | 30 min timeout |
| 18 | **amass** | Comprehensive enum framework | ❌ Removed | N/A | No longer used |

### Phase 2 — Intelligence Gathering (16 Tools)

| # | Tool | Purpose | Status | API Key Required | Notes |
|---|------|---------|--------|-----------------|-------|
| 19 | **subprober** | Subdomain validation | ✅ Working | No | Built-in validation |
| 20 | **dnsx** | DNS validation | ✅ Working | No | Reused from Phase 1 |
| 21 | **rustscan** | Fast port scanner (Rust) | ✅ Working | No | Alternative to nmap |
| 22 | **nmap** | Comprehensive port scanning | ✅ Working | No | Primary port scanner |
| 23 | **shodan** | Shodan API integration | ✅ Working | `SHODAN_API_KEY` | Host/port/banner lookups |
| 24 | **shodanx** | Extended Shodan queries | ✅ Working | `SHODAN_API_KEY` | Extended queries |
| 25 | **dorker** | Google dork automation | ✅ Working | No | Search results |
| 26 | **censys** | Censys API integration | ✅ Working | `CENSYS_API_ID` + `CENSYS_API_SECRET` | Certificate + host search |
| 27 | **whois** | WHOIS data gathering | ✅ Working | No | Reused from Phase 1 |
| 28 | **subover** | Subdomain takeover detection | ✅ Working | No | CNAME checks |
| 29 | **gitleaks** | Secret scanning in repos | ✅ Working | No | Cross-phase |
| 30 | **gh** | GitHub CLI tool | ✅ Working | `GITHUB_TOKEN` | GitHub searching |
| 31 | **githunt** | GitHub secret hunting | ✅ Working | `GITHUB_TOKEN` | Secret hunting |
| 32 | **trufflehog** | Secret detection tool | ✅ Working | No | Cross-phase |
| 33 | **git-secrets** | Git hook for secret detection | ✅ Working | No | Local repo scanning |
| 34 | *(15th tool slot reused)* | — | — | — | — |

### Phase 3 — Content Discovery (16 Tools)

| # | Tool | Purpose | Status | API Key Required | Notes |
|---|------|---------|--------|-----------------|-------|
| 35 | **gau** | Get All URLs (Wayback, Common Crawl) | ✅ Working | No | Archive-based URL discovery |
| 36 | **waybackurls** | Wayback Machine URL scraper | ✅ Working | No | Historical endpoints |
| 37 | **spideyx** | Powerful spider tool | ✅ Working | No | Primary crawler |
| 38 | **hakrawler** | Web crawler | ✅ Working | No | Crawls discovered URLs |
| 39 | **katana** | Advanced web crawler | ✅ Working | No | Fast with JS support |
| 40 | **cariddi** | Endpoint discovery | ✅ Working | No | Alternative crawler |
| 41 | **mantra** | Web spider tool | ✅ Working | No | Another crawler option |
| 42 | **gitleaks** | Secret scanning in downloaded content | ✅ Working | No | Scans files |
| 43 | **trufflehog** | Secret detection in content | ✅ Working | No | Scans files |
| 44 | **ffuf** | Directory/parameter fuzzing | ❌ Broken | No | JSON parsing bug |
| 45 | **feroxbuster** | Recursive directory discovery | ✅ Working | No | Alternative dir fuzzer |
| 46 | **dirsearch** | Directory brute-forcing | ✅ Working | No | Standard dir scanner |
| 47 | **linkfinder** | JavaScript endpoint extractor | ✅ Working | No | Finds API endpoints in JS |
| 48 | **jsscanner** | JavaScript security scanner | ✅ Working | No | Scans JS for issues |
| 49 | **pbin** | Pastebin monitoring | ✅ Working | `PASTEBIN_API_KEY` | Leaked data checks |

### Phase 4 — Vulnerability Scanning (13 Tools)

| # | Tool | Purpose | Status | API Key Required | Notes |
|---|------|---------|--------|-----------------|-------|
| 50 | **nuclei** | Multi-purpose vuln scanner | ✅ Working | No | Primary scanner; templates |
| 51 | **dalfox** | XSS vulnerability scanner | ✅ Working | No | Specialized XSS |
| 52 | **sqlmap** | SQL injection detection | ✅ Working | No | Automated SQLi |
| 53 | **corsy** | CORS misconfiguration finder | ✅ Working | No | Cross-origin checks |
| 54 | **nikto** | Web server scanner | ✅ Working | No | Comprehensive web vuln |
| 55 | **wpscan** | WordPress vuln scanner | ✅ Working | `WPSCAN_API_TOKEN` | WordPress CVE DB |
| 56 | **wapiti** | Web app vuln scanner | ✅ Working | No | General web scanner |
| 57 | **skipfish** | Web security scanner | ✅ Working | No | Alternative scanner |
| 58 | **cmsmap** | CMS vuln scanner | ✅ Working | No | WordPress/Joomla/Drupal |
| 59 | **retire** | JS library vuln scanner | ✅ Working | No | Vulnerable JS libraries |
| 60 | **testssl.sh** | SSL/TLS security checker | ✅ Working | No | Certificate / SSL analysis |
| 61 | **sslyze** | SSL/TLS analyzer | ✅ Working | No | Deep SSL analysis |
| 62 | **gowitness** | Web page screenshot tool | ✅ Working | No | Visual validation |

### Cross-Phase & Utility Tools (4 Tools)

| Tool | Purpose | Used In |
|------|---------|---------|
| **jq** | JSON data processor | Phase 3, 4 |
| **timeout / run_timeout** | Command timeout utility | All phases |
| **Python parsers** | Output parsing into DB | All phases |
| **SQLite Database** | Results storage (25+ ORM models) | All phases |

### Tool Status Summary

| Metric | Count |
|--------|-------|
| **Total Tools** | 57 |
| **Working** | 55 |
| **Broken** | 1 (ffuf — parser bug) |
| **Removed** | 1 (amass) |
| **Success Rate** | **96.5%** |

---

## 4. Complete API Key Reference (22 Keys)

### Setup

```bash
cp .env.example .env
nano .env  # Add your API keys
```

### Full Reference Table

| # | Variable | Service | Used In | Required? | Get It At |
|---|----------|---------|---------|-----------|-----------|
| 1 | `SHODAN_API_KEY` | Shodan | Phase 2 — host/port/banner lookups | **Recommended** | https://account.shodan.io |
| 2 | `CENSYS_API_ID` | Censys | Phase 2 — certificate + host search | Optional | https://search.censys.io/account/api |
| 3 | `CENSYS_API_SECRET` | Censys | Phase 2 — (same account as ID) | Optional | https://search.censys.io/account/api |
| 4 | `SECURITYTRAILS_API_KEY` | SecurityTrails | Phase 1 — historical DNS / subdomains | **Recommended** | https://securitytrails.com/app/account/credentials |
| 5 | `VT_API_KEY` | VirusTotal | Phase 1 & 4 — URL/file reputation | **Recommended** | https://www.virustotal.com/gui/my-apikey |
| 6 | `GITHUB_TOKEN` | GitHub | Phase 2 — secret / code leak search | **Recommended** | https://github.com/settings/tokens |
| 7 | `ABUSEIPDB_API_KEY` | AbuseIPDB | Threat intel — IP reputation | Optional | https://www.abuseipdb.com/account/api |
| 8 | `GREYNOISE_API_KEY` | GreyNoise | Threat intel — noise/scanner IPs | Optional | https://viz.greynoise.io/account/your-api-key |
| 9 | `OTX_API_KEY` | AlienVault OTX | Threat intel — IoC feeds | Optional | https://otx.alienvault.com/api |
| 10 | `HIBP_API_KEY` | Have I Been Pwned | Phase 2 — data-breach email check | Optional | https://haveibeenpwned.com/API/Key |
| 11 | `EMAILREP_API_KEY` | EmailRep.io | Threat intel — email reputation | Optional | https://emailrep.io/key |
| 12 | `URLSCAN_API_KEY` | URLScan.io | Phase 3 — page screenshot/analysis | Optional | https://urlscan.io/user/profile/ |
| 13 | `PULSEDIVE_API_KEY` | Pulsedive | Threat intel — enrichment | Optional | https://pulsedive.com/dashboard/?key |
| 14 | `BINARYEDGE_API_KEY` | BinaryEdge | Phase 2 — internet-wide scan data | Optional | https://app.binaryedge.io/account/api |
| 15 | `CROWDSEC_API_KEY` | CrowdSec | Threat intel — community blocklist | Optional | https://app.crowdsec.net/settings/api-keys |
| 16 | `GSB_API_KEY` | Google Safe Browsing | Phase 4 — URL safety check | Optional | https://developers.google.com/safe-browsing/v4/get-started |
| 17 | `WPSCAN_API_TOKEN` | WPScan | Phase 4 — WordPress CVE DB | Optional | https://wpscan.com/profile |
| 18 | `PASTEBIN_API_KEY` | Pastebin | Phase 3 — paste monitoring | Optional | https://pastebin.com/api |
| 19 | `NVD_API_KEY` | NVD (NIST) | Phase 4 — CVE lookups (rate-limit bypass) | Optional | https://nvd.nist.gov/developers/request-an-api-key |
| 20 | `DEHASHED_API_KEY` | DeHashed | Threat intel — credential leaks | Optional | https://www.dehashed.com/profile |
| 21 | `DEHASHED_EMAIL` | DeHashed | Threat intel — account email | Optional | (same account) |
| 22 | `INTELX_API_KEY` | Intelligence X | OSINT — deep/dark web search | Optional | https://intelx.io/account |

### Minimum Viable Key Set (Recommended for First Scan)

```bash
SHODAN_API_KEY=your_key_here
SECURITYTRAILS_API_KEY=your_key_here
VT_API_KEY=your_key_here
GITHUB_TOKEN=ghp_your_token_here
```

> **Note:** All API keys are **optional**. Technieum runs with reduced coverage when a key is missing — it skips that specific lookup and logs a warning. No scan will fail due to a missing key.

---

## 5. API Key Pricing & Free Tiers

### Completely Free APIs (No Payment Required)

| Service | Free Tier Limits | Notes |
|---------|-----------------|-------|
| **Shodan** | 100 queries/month | Free account at shodan.io |
| **Censys** | 250 queries/month | Free community plan |
| **SecurityTrails** | 50 API calls/month | Free plan available |
| **VirusTotal** | 4 requests/min, 500/day | Free public API |
| **GitHub** | 5,000 requests/hour | Free personal access token (`public_repo` scope) |
| **AbuseIPDB** | 1,000 checks/day | Free plan |
| **GreyNoise** | Unlimited (basic data) | Free community edition |
| **AlienVault OTX** | 10,000 requests/hour | Completely free |
| **EmailRep.io** | 200 queries/day | Free plan |
| **URLScan.io** | 100 scans/day | Free plan |
| **Pulsedive** | 30 req/min, 1,000/month | Free plan |
| **BinaryEdge** | 250 queries/month | Free plan |
| **CrowdSec** | 50 requests/day | Free community plan |
| **Google Safe Browsing** | Unlimited | Free, **non-commercial use only** |
| **NVD (NIST)** | Rate-limited without key | Free API key removes rate limits |
| **Pastebin** | Varies | Free API key |
| **WPScan** | 25 requests/day | Free plan |
| **PhishTank** | Unlimited | Free with app key |

### Paid APIs (Optional — For Extended Coverage)

| Service | Free Tier | Paid Plans Start At | Notes |
|---------|-----------|-------------------|-------|
| **Have I Been Pwned (HIBP)** | No free tier for API | $3.50/month | Email/domain breach check |
| **DeHashed** | No free tier for API | $5.49/month | Credential leak database |
| **Intelligence X** | Limited free tier | $2,000+/year | Deep/dark web intelligence |
| **Shodan** (Membership) | 100 queries/month free | $69/lifetime or $59/month enterprise | Unlocks scan credits + filters |

### Total Cost to Run Technieum

| Setup | Monthly Cost | Coverage |
|-------|-------------|----------|
| **Free tier only** | **$0** | ~85% coverage (most tools work without keys) |
| **Recommended free keys** | **$0** | ~95% coverage (4 free API keys) |
| **Full coverage (all keys)** | **~$10–15/month** | 100% coverage (add HIBP + DeHashed) |
| **Enterprise** | **$100+/month** | Full coverage + high rate limits |

---

## 6. REST API Reference

### Starting the API Server

```bash
source .venv/bin/activate
python3 -m uvicorn backend.api.server:app --host 0.0.0.0 --port 8000

# With auto-reload (development)
python3 -m uvicorn backend.api.server:app --reload --port 8000
```

### Authentication

All endpoints (except `/health` and `/version`) require an API key.

**Send key via header:**
```bash
# X-API-Key header (recommended)
curl -H "X-API-Key: <your-key>" http://localhost:8000/api/v1/scans/

# Bearer token
curl -H "Authorization: Bearer <your-key>" http://localhost:8000/api/v1/scans/
```

**Create an API key:**
```bash
source .venv/bin/activate
python3 - <<'EOF'
import hashlib, os, sys
sys.path.insert(0, '.')
os.environ.setdefault("DATABASE_URL", "sqlite:///./technieum.db")
from backend.db.database import SessionLocal
from backend.db.models import APIToken
from datetime import datetime, timedelta
key = os.urandom(32).hex()
key_hash = hashlib.sha256(key.encode()).hexdigest()
db = SessionLocal()
token = APIToken(
    token_hash=key_hash, user_name="admin",
    token_type="bearer", is_active=True,
    expires_at=datetime.utcnow() + timedelta(days=365),
)
db.add(token); db.commit(); db.close()
print(f"\nYour API key (save this — shown only once):\n\n  {key}\n")
EOF
```

### Complete Endpoint Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/health` | ❌ No | Health check |
| `GET` | `/version` | ❌ No | API version |
| **Scans** | | | |
| `GET` | `/api/v1/scans/` | ✅ Yes | List scans (paginated) |
| `POST` | `/api/v1/scans/` | ✅ Yes | Create a new scan |
| `GET` | `/api/v1/scans/{id}` | ✅ Yes | Get scan details |
| `POST` | `/api/v1/scans/{id}/start` | ✅ Yes | Start a scan |
| `POST` | `/api/v1/scans/{id}/stop` | ✅ Yes | Stop a running scan |
| `GET` | `/api/v1/scans/{id}/progress` | ✅ Yes | Get scan progress (SSE) |
| **Findings** | | | |
| `GET` | `/api/v1/findings/` | ✅ Yes | List findings (paginated, filterable) |
| `GET` | `/api/v1/findings/by-severity` | ✅ Yes | Findings grouped by severity |
| `PATCH` | `/api/v1/findings/{id}` | ✅ Yes | Update a finding |
| **Assets** | | | |
| `GET` | `/api/v1/assets/` | ✅ Yes | List discovered assets |
| `GET` | `/api/v1/assets/search` | ✅ Yes | Search assets by keyword |
| **Intelligence** | | | |
| `GET` | `/api/v1/intel/threat-feed` | ✅ Yes | Threat intelligence feed |
| **Reports** | | | |
| `GET` | `/api/v1/reports/` | ✅ Yes | List generated reports |
| `POST` | `/api/v1/reports/` | ✅ Yes | Generate a new report |
| **Webhooks** | | | |
| `GET` | `/api/v1/webhooks/` | ✅ Yes | List registered webhooks |
| `POST` | `/api/v1/webhooks/` | ✅ Yes | Register a new webhook |
| **Stream** | | | |
| `GET` | `/api/v1/stream/` | ✅ Yes | SSE real-time event stream |

**Interactive API Docs:** `http://localhost:8000/docs` (Swagger UI)

### Security Features

| Feature | Description |
|---------|-------------|
| **JWT Authentication** | Token-based auth with configurable expiry |
| **API Key Auth** | SHA-256 hashed keys stored in DB |
| **Rate Limiting** | Configurable requests/window (default: 100/hour) |
| **CSRF Protection** | Middleware-level CSRF token validation |
| **Request Logging** | All requests logged with metadata |

---

## 7. Web Dashboard

### Available Pages

| URL Path | Page | Features |
|----------|------|----------|
| `/` | **Main Dashboard** | Scan status overview, top findings, statistics |
| `/findings_v2.html` | **Findings Explorer** | Filter by severity/type/status, export data |
| `/scan_viewer_v2.html` | **Live Scan Monitor** | Real-time SSE progress, phase tracking, logs |
| `/graph_viewer_v2.html` | **Attack-Path Graph** | NetworkX-based attack path visualisation |

### Dashboard Features

- **Real-time monitoring** via Server-Sent Events (SSE)
- **Dark theme** with glassmorphism design
- **Export capabilities** — TXT, JSON, CSV for all data panels
- **Collapsible panels** — Live Hosts, ASN/CIDR, WHOIS, DNS, Cloud, Certificates, Scan Details, Logs
- **Assessment management** — Create, monitor, view, retry, delete assessments
- **Search & filter** — Filter assessments by status (Running/Completed/Failed)
- **Pagination** — Navigate through large result sets

### UI Design

| Element | Value |
|---------|-------|
| Primary Color | Orange (#FF8C00) |
| Gradient | #FFD84D → #FF8C00 → #FF2D00 |
| UI Font | Inter |
| Code Font | JetBrains Mono |
| Theme | Dark with glassmorphism & blur effects |

---

## 8. Installation & Setup

### System Requirements

| Requirement | Version | Notes |
|-------------|---------|-------|
| Linux | Any modern distro | Tested on Kali 2024.x, Ubuntu 22.04+, Debian 12+ |
| Python | 3.11+ | Required for `tomllib`, `ExceptionGroup` |
| Go | 1.22+ | Installed automatically by `install.sh` |
| SQLite | 3.35+ | Usually pre-installed |
| RAM | 2 GB+ min | 4 GB recommended for full scans |
| Disk | 5 GB+ | For wordlists and tool binaries |

### Automated Installation (Recommended)

```bash
# Clone
git clone https://github.com/your-org/technieum-x.git
cd technieum-x

# Full install (~10-20 min)
sudo bash install.sh

# Optional flags
sudo bash install.sh --python-only      # Skip Go tools
sudo bash install.sh --skip-wordlists   # Skip SecLists download

# Activate venv
source .venv/bin/activate

# Verify
bash setup.sh
```

### Manual Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
mkdir -p output logs
cp .env.example .env
nano .env  # Add your API keys
```

### Post-Install: Add API Keys

```bash
cp .env.example .env
nano .env
# Fill in your keys (see Section 4 for full reference)
```

---

## 9. Configuration Reference

### config.yaml — Key Settings

```yaml
general:
  output_dir: "output"
  database: "technieum.db"
  threads: 5                    # Concurrent scan workers
  timeout: 3600                 # Per-phase timeout (seconds)

phase1_discovery:
  enabled: true
  subdomain_tools: [subfinder, assetfinder, subdominator, crtsh, securitytrails]
  dns_resolution: { tool: dnsx, timeout: 10 }
  http_validation: { tool: httpx, threads: 50, timeout: 10 }

phase2_intel:
  enabled: true
  port_scanning: { fast_scan: true, deep_scan: true, nmap_flags: "-sV -sC -T4 -Pn" }
  osint: { shodan: true, censys: true }

phase3_content:
  enabled: true
  directory_bruteforce: { tools: [ffuf, feroxbuster, dirsearch], threads: 50 }
  js_analysis: { linkfinder: true, secretfinder: true }

phase4_vulnscan:
  enabled: true
  nuclei: { severity: [critical, high, medium, low, info], rate_limit: 150 }
  xss: { tool: dalfox, max_urls: 100 }
  sqli: { tool: sqlmap, sqlmap_flags: "--batch --random-agent --level=1 --risk=1" }
  ssl_tls: { tool: testssl, max_hosts: 10 }

notifications:
  slack_webhook: ""
  discord_webhook: ""
```

### Environment Variable Timeouts

```bash
# Discovery Phase
TECHNIEUM_WHOIS_TIMEOUT=60
TECHNIEUM_SUBFINDER_TIMEOUT=900
TECHNIEUM_DNSX_TIMEOUT=1800
TECHNIEUM_HTTPX_TIMEOUT=15
TECHNIEUM_HTTPX_RUN_TIMEOUT=3600

# Intelligence Phase
TECHNIEUM_RUSTSCAN_TIMEOUT=900
TECHNIEUM_NMAP_TIMEOUT=900
TECHNIEUM_SHODAN_TIMEOUT=900

# Content Discovery
TECHNIEUM_FFUF_TIMEOUT=1800
TECHNIEUM_FEROXBUSTER_TIMEOUT=1800
TECHNIEUM_DIRSEARCH_TIMEOUT=1800

# Vulnerability Phase
TECHNIEUM_NUCLEI_TIMEOUT=3600
TECHNIEUM_SQLMAP_TIMEOUT=1800
TECHNIEUM_TESTSSL_TIMEOUT=900
```

### Feature Flags

```bash
TECHNIEUM_NUCLEI_UPDATE=false          # Auto-update nuclei templates
TECHNIEUM_CONTINUE_ON_FAIL=true        # Continue if a tool fails
TECHNIEUM_SKIP_KNOWN_BROKEN_TOOLS=false # Skip known broken tools
```

---

## 10. Usage Guide

### CLI Usage

```bash
source .venv/bin/activate

# Basic scan (all 4 phases)
python3 technieum.py -t example.com

# Specify output directory
python3 technieum.py -t example.com -o /tmp/example-scan

# Run with more threads
python3 technieum.py -t example.com --threads 10

# Single phase
python3 technieum.py -t example.com --phase 1

# Multiple phases
python3 technieum.py -t example.com --phases 1,2

# Resume interrupted scan
python3 technieum.py -t example.com --resume

# Multiple targets
python3 technieum.py --targets-file targets.txt
python3 technieum.py -t "example.com,corp.example.com"

# Dry run (print what would run)
python3 technieum.py -t example.com --dry-run

# Verbose output
python3 technieum.py -t example.com -v
```

### Query Results

```bash
python3 query.py                                          # Interactive
python3 query.py --target example.com --show subdomains   # Show subdomains
python3 query.py --target example.com --show vulns --severity critical,high
python3 query.py --target example.com --export json > results.json
```

### Output Structure

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
    │   ├── ports.txt
    │   ├── ssl_certs.json
    │   └── github_leaks.txt
    ├── phase3/
    │   ├── directories.txt
    │   ├── js_secrets.txt
    │   ├── s3_buckets.txt
    │   └── technologies.json
    └── phase4/
        ├── nuclei_results.json     # CVSS scored
        ├── sqlmap_results/
        ├── ssl_issues.txt
        └── summary.json            # Phase summary with risk score
```

---

## 11. Intelligence Engine

### Components

| Module | Purpose | Technology |
|--------|---------|-----------|
| **Risk Scoring** | CVSS-based scoring with custom weighting | Python + CVSS calculator |
| **Attack Graph** | Graph-based attack path analysis | NetworkX |
| **Change Detection** | Track asset changes across scans, generate alerts | Python comparators |
| **Threat Intel** | Multi-source threat intelligence aggregation | API integrations |
| **Compliance** | Security compliance checking | Rule engine |

### How Intelligence Works

1. **Risk Scoring:** Every finding receives a CVSS score. Custom weights are applied based on asset criticality, exposure, and exploitability. Scores propagate through the attack graph.

2. **Attack Graph:** NetworkX builds a directed graph connecting assets → services → vulnerabilities. Identifies shortest attack paths and high-value targets.

3. **Change Detection:** Compares current scan results with previous scans. Generates alerts for new subdomains, changed services, new vulnerabilities, and removed assets.

4. **Threat Intel:** Aggregates data from Shodan, Censys, GreyNoise, AbuseIPDB, OTX, and VirusTotal to enrich findings with real-world threat context.

5. **Compliance:** Checks discovered assets against security baselines (SSL/TLS configuration, security headers, exposed services).

---

## 12. Docker Deployment

### Quick Start

```bash
# Copy environment template
cp .env.docker.example .env.docker

# Edit with your API keys
nano .env.docker

# Build and run
docker-compose up -d

# Production mode
docker-compose -f docker-compose.prod.yml up -d
```

### Docker Configuration

```bash
# .env.docker key settings
TECHNIEUM_ENV=production
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=4
DATABASE_URL=sqlite:////data/technieum.db
REDIS_HOST=redis
REDIS_PORT=6379
JWT_SECRET=your-super-secret-jwt-key-change-this
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=3600
```

### Docker Compose Services

| Service | Purpose |
|---------|---------|
| **technieum** | Main application (API + scanner) |
| **redis** | Caching and job queue (optional) |
| **nginx** | Reverse proxy with SSL (optional) |

---

## 13. Troubleshooting

| Problem | Solution |
|---------|----------|
| `externally-managed-environment` error | Use venv: `source .venv/bin/activate` |
| Go tools not found | `export PATH="$PATH:$HOME/go/bin"` |
| Database errors / tables missing | Recreate schema (see README) |
| Port 8000 already in use | `python3 -m uvicorn ... --port 8080` |
| Nuclei templates outdated | `nuclei -update-templates` |
| Permission denied on scan modules | `chmod +x modules/*.sh` |
| Rate-limited by APIs | Reduce `threads` in `config.yaml` or upgrade API plan |
| SQLite WAL lock issues | `sqlite3 technieum.db "PRAGMA journal_mode=WAL;"` |
| ffuf results missing | Known parser bug — use `feroxbuster` or `dirsearch` as alternatives |

---

## 14. License & Legal

**License:** MIT — see [LICENSE](../LICENSE) for full text.

**Copyright:** © 2024 Technieum Contributors

> ⚠️ **Legal Disclaimer:** This tool is intended for **authorised security assessments only**. Always obtain **written permission** before scanning any system you do not own. Users are responsible for complying with all applicable local, state, national, and international laws. The developers assume no liability for misuse.

---

*Documentation generated: March 25, 2026*
*Technieum Version: Latest*
*Total Tools Integrated: 57 | APIs: 22 | Working: 96.5%*
