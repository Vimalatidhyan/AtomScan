# Technieum Documentation Index

Welcome to the complete Technieum documentation. Start here to find what you need.

---

## 📖 Main Documentation

### [README.md](README.md) - Start Here
**Complete guide covering everything at a non-technical, understandable level**
- What Technieum is and how it works
- The 4-phase approach explained
- What's currently working
- What's planned for the future
- Common use cases
- Quick command reference
- ~500 lines, easy to read, no code

**Read this if:** You're new to Technieum or want a complete overview

---

## 🚀 Getting Started

### Quick Start Commands
```bash
# Install and setup
bash setup.sh
pip3 install -r requirements.txt

# Run your first scan
python3 technieum.py -t example.com

# Query results
python3 query.py -t example.com --summary
```

### Configuration
Edit `config.yaml` in the root directory to:
- Add API keys for tools (Shodan, HunterIO, etc.)
- Customize which tools to run
- Set scanning intensity levels
- Configure output preferences

---

## 📋 Documentation Breakdown

| Document | Purpose | Best For |
|----------|---------|----------|
| **README.md** | Complete overview | Everyone - start here |
| **CAPABILITIES.md** | Detailed features | Understanding what's possible |
| **TOOLS.md** | All 50+ tools documented | Deep tool knowledge |
| **PHASES.md** | 4-phase workflow details | Understanding the process |
| **USE_CASES.md** | Real-world examples | Learning by example |
| **QUICK_REFERENCE.md** | Commands & syntax | Daily usage |
| **TROUBLESHOOTING.md** | Problems & solutions | When things go wrong |
| **FAQ.md** | Common questions | Quick answers |

---

## The Four Phases (Quick Overview)

### Phase 1: Discovery
Finding all subdomains using 5 enumeration tools
- Status: ✅ Working
- Tools: Subfinder, Amass, assetfinder, crt.sh, WHOIS

### Phase 2: Intelligence Gathering
Validating live hosts and open ports
- Status: ✅ Working
- Tools: HTTPx, DNSx, Nmap, RustScan, Masscan

### Phase 3: Content Discovery
Mapping web applications and endpoints
- Status: ✅ Working
- Tools: GAU, Katana, FFUF, Dirsearch, JavaScript Parser, Waybackurls

### Phase 4: Vulnerability Scanning
Testing for security vulnerabilities
- Status: ✅ Working
- Tools: Nuclei, Dalfox, SQLMap, Corsy, Gitleaks

---

## Current Capabilities (What Works Now)

✅ **AutomationWork**
- Orchestrate 50+ security tools
- Proper sequencing of phases
- Automatic error recovery
- Resume if interrupted

✅ **Data Storage**
- Permanent SQLite database
- Searchable results
- Relationship mapping
- Deduplication

✅ **Results Access**
- Command-line querying
- CSV export
- Summary views
- Filtered searches

✅ **Flexibility**
- Run individual phases
- Scan multiple targets
- Custom configuration
- Tool selection per run

---

## Planned Capabilities (Phase A)

🔄 **REST API**
- Programmatic access
- JSON responses
- Cloud-ready
- Integration hooks

🔄 **Web Dashboard**
- Browser-based UI
- Visual attack surface
- Real-time progress
- Interactive reports

🔄 **Report Generation**
- PDF reports
- HTML reports
- CSV data export
- Executive summaries

🔄 **Docker Support**
- Containerized deployment
- Cloud-ready
- Compose setup
- Kubernetes-compatible

🔄 **Scheduled Scanning** (Phase B)
- Recurring scans
- Change detection
- Slack/Discord alerts
- Custom alerting rules

---

## Common Tasks

### Scan a Single Domain
```bash
python3 technieum.py -t example.com
```

### Scan Multiple Domains
```bash
python3 technieum.py -t example.com,other.com,third.com
```

### Run Only Specific Phases
```bash
python3 technieum.py -t example.com --phases 1,2
```

### Resume a Scan
```bash
python3 technieum.py -t example.com --resume
```

### Query Results
```bash
# Get summary
python3 query.py -t example.com --summary

# List all subdomains
python3 query.py -t example.com --subdomains

# List vulnerabilities
python3 query.py -t example.com --vulnerabilities

# Export to CSV
python3 query.py -t example.com --export csv

# Find specific port
python3 query.py -t example.com --port 443
```

---

## Tools Integrated (50+)

### Discovery Tools (7)
Subfinder, Amass, assetfinder, crt.sh, WHOIS, Passive DNS, Certificate Transparency

### Validation Tools (5)
HTTPx, DNSx, Nmap, RustScan, Masscan

### Content Discovery Tools (8)
GAU, Katana, FFUF, Dirsearch, Feroxbuster, JavaScript Parser, Waybackurls, Commoncrawl

### Scanning Tools (10+)
Nuclei, Dalfox, SQLMap, Corsy, Gitleaks, TruffleHog, and more

---

## Database Structure

All results stored in SQLite with these main tables:
- **subdomains** - Discovered domains
- **ports** - Open ports and services
- **urls** - Web endpoints
- **vulnerabilities** - Found security issues
- **leaks** - Exposed secrets/data
- **tool_runs** - Execution history
- Plus metadata and relationship tables

All data is queryable and exportable.

---

## System Requirements

| Requirement | Details |
|-------------|---------|
| **Python** | 3.11 or higher |
| **OS** | Linux, macOS (Windows with WSL) |
| **Storage** | 2GB minimum for database + tools |
| **Network** | Internet connection required |
| **Tools** | 50+ tools installed during setup |

---

## Installation Methods

### Method 1: Automated Setup (Recommended)
```bash
bash setup.sh
pip3 install -r requirements.txt
```

### Method 2: Docker
Coming in Phase A

### Method 3: Manual
Follow tool installation guides for each of the 50+ tools

---

## Project Structure

```
/
├── technieum.py              Main orchestrator
├── query.py               Results interface
├── config.yaml            Configuration
├── requirements.txt       Python dependencies
├── setup.sh               Installation script
├── modules/               Phase execution scripts
│   ├── 01_discovery.sh
│   ├── 02_intel.sh
│   ├── 03_content.sh
│   └── 04_vuln.sh
├── db/                    Database code
│   └── database.py        SQLite manager
├── parsers/               Output parsing
│   └── parser.py          Tool output handlers
├── output/                Results storage
│   └── {target}/
│       ├── phase1_discovery/
│       ├── phase2_intel/
│       ├── phase3_content/
│       └── phase4_vulnscan/
├── examples/              Example scripts
└── docs/                  Documentation (this folder)
    ├── README.md
    ├── INDEX.md
    ├── CAPABILITIES.md
    ├── TOOLS.md
    ├── PHASES.md
    ├── USE_CASES.md
    ├── QUICK_REFERENCE.md
    ├── TROUBLESHOOTING.md
    └── FAQ.md
```

---

## For Different Users

### I'm New to Technieum
1. Read [README.md](README.md) - Full overview
2. Follow quick start commands above
3. Run your first scan
4. Check [QUICK_REFERENCE.md](QUICK_REFERENCE.md) for common commands

### I Want to Understand How It Works
1. Read [PHASES.md](PHASES.md) - 4-phase workflow
2. Read [TOOLS.md](TOOLS.md) - All 50+ tools explained
3. Check [CAPABILITIES.md](CAPABILITIES.md) - What's possible

### I'm Running It in Production
1. Review [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
2. Check [USE_CASES.md](USE_CASES.md) for production patterns
3. Set up database backups (in `/db` folder)
4. Configure API keys in config.yaml

### I Found a Problem
1. Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md) first
2. Check [FAQ.md](FAQ.md) for common issues
3. Review error messages carefully
4. Check tool-specific documentation

### I Want to Contribute
1. Understand [PHASES.md](PHASES.md) - How tools are organized
2. Review custom tool/parser examples
3. Follow contributing guidelines
4. Submit improvements

---

## Phase A Features (Coming Soon)

When Phase A launches, you'll get:

### REST API (Programmatic Access)
```
POST /api/scans - Create new scan
GET /api/scans/{id} - Get scan status
GET /api/scans/{id}/subdomains - List subdomains
GET /api/scans/{id}/vulnerabilities - List vulnerabilities
GET /api/scans/{id}/export - Export results
DELETE /api/scans/{id} - Delete scan
... and more
```

### Web Dashboard
- Target list
- Active scans
- Finding explorer
- Report generator
- Settings panel

### Report Generation
- PDF reports for management
- HTML reports for sharing
- CSV exports for analysis
- Executive summaries
- Technical details

### Docker
```bash
docker-compose up
# Access at http://localhost:8000
```

---

## Support Options

| Need | Resource |
|------|----------|
| **How to use** | [README.md](README.md) |
| **Command syntax** | [QUICK_REFERENCE.md](QUICK_REFERENCE.md) |
| **Something broken** | [TROUBLESHOOTING.md](TROUBLESHOOTING.md) |
| **Quick question** | [FAQ.md](FAQ.md) |
| **Real-world examples** | [USE_CASES.md](USE_CASES.md) |
| **Details on tools** | [TOOLS.md](TOOLS.md) |
| **How phases work** | [PHASES.md](PHASES.md) |
| **Feature list** | [CAPABILITIES.md](CAPABILITIES.md) |

---

## Next Steps

### This Week
- [ ] Install Technieum (`bash setup.sh`)
- [ ] Run a test scan (`python3 technieum.py -t example.com`)
- [ ] Query the results (`python3 query.py -t example.com --summary`)
- [ ] Explore the database (`sqlite3 db/results.db`)

### This Month
- [ ] Scan your own domains
- [ ] Understand the 4-phase approach
- [ ] Set up regular scanning
- [ ] Share findings with your team

### Looking Ahead
- [ ] Wait for Phase A (REST API, Dashboard, Reports)
- [ ] Plan your integration approach
- [ ] Monitor the roadmap
- [ ] Share feedback on features

---

## Quick Links

- **Main documentation:** [README.md](README.md)
- **Phase details:** [PHASES.md](PHASES.md)
- **Tool information:** [TOOLS.md](TOOLS.md)
- **Command reference:** [QUICK_REFERENCE.md](QUICK_REFERENCE.md)
- **Troubleshooting:** [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- **FAQ:** [FAQ.md](FAQ.md)

---

## Version Information

- **Technieum Version:** 1.0
- **Status:** Production Ready (CLI)
- **Phase:** A (REST API, Dashboard, Reports) planned for Q2 2026
- **Last Updated:** February 2026

---

**Start with [README.md](README.md) → Run a scan → Check [QUICK_REFERENCE.md](QUICK_REFERENCE.md) for your needs**

Happy reconnaissance! 🛡️
