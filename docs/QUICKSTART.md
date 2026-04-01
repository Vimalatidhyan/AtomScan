# Technieum Quick Start Guide

**Goal:** Get Technieum running and understand the full project in under 30 minutes

---

## Part 1: Understand What Technieum Does (5 minutes)

Technieum is an **Attack Surface Management platform** that finds everything on your digital footprint:

```
Your Domain
    ↓
Technieum Phase 1: Find subdomains (thousands)
    ↓
Technieum Phase 2: Scan ports, check for leaks
    ↓
Technieum Phase 3: Discover URLs, APIs, endpoints
    ↓
Technieum Phase 4: Test for vulnerabilities (XSS, SQLi, etc.)
    ↓
Results Database
    ↓
Reports/API Access
```

---

## Part 2: Install Technieum (5 minutes)

```bash
# 1. Navigate to project
cd /Users/rejenthompson/Documents/technieum-/kali-linux-asm

# 2. Run setup (installs minimum dependencies)
bash setup.sh

# 3. Install Python packages
pip3 install -r requirements.txt

# 4. (Optional) Install all 50+ tools
sudo bash install.sh          # Takes 20-30 minutes
```

**Check it works:**
```bash
python3 technieum.py --help      # Should show help text
```

---

## Part 3: Run Your First Scan (10 minutes)

```bash
# Scan example.com
python3 technieum.py -t example.com

# Watch it run - you'll see:
# [+] Phase 1: Discovery & Enumeration for example.com
# [+] Running sublist3r...
# [+] Running amass...
# [+] Running subfinder...
# ... (continues for 1-2 hours depending on domain size)
```

**While it runs**, open another terminal:

```bash
# See raw outputs
ls -la output/example_com/phase1_discovery/

# Check database growing
sqlite3 technieum.db "SELECT COUNT(*) FROM subdomains"
```

---

## Part 4: Query Results (5 minutes)

Once Phase 1 completes:

```bash
# See summary
python3 query.py -t example.com --summary

# See all subdomains found
python3 query.py -t example.com --subdomains

# See only alive subdomains
python3 query.py -t example.com --subdomains --alive-only

# See vulnerabilities (after Phase 4)
python3 query.py -t example.com --vulns

# Export to CSV
python3 query.py -t example.com --export subdomains -o subs.csv
python3 query.py -t example.com --export vulnerabilities -o vulns.csv
```

---

## Part 5: Understand the Full Picture (5-10 minutes)

Now read the proper documentation:

### Start here:
- **[DOCUMENTATION.md](DOCUMENTATION.md)** ← Complete guide (8000+ words)
  - Architecture (how it works)
  - Each phase in detail
  - Database schema
  - All CLI commands
  - Planned features (REST API, Dashboard, etc.)

### Quick lookup:
- **[DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md)** ← Quick reference (500 words)
  - Status summary
  - Phase overview
  - Links to all sections

### For development:
- **[REFACTOR_PROMPT.md](REFACTOR_PROMPT.md)** ← 4 Claude prompts
  - Phase A: REST API, Dashboard, Reports (2-3 weeks work)
  - Phase B: Scheduling, Alerts, Tracking (3-4 weeks work)
  - Phase C: Multi-tenant, RBAC, Jira (4-5 weeks work)
  - Phase D: PostgreSQL, Workers, Plugins (4-6 weeks work)

---

## Part 6: What to Do Next

### Option 1: Scan Your Own Assets
```bash
# Create targets file
echo "your-domain.com" > targets.txt
echo "another-site.com" >> targets.txt

# Scan all
python3 technieum.py -f targets.txt -T 5

# Get report
python3 query.py --list
python3 query.py -t your-domain.com --summary
```

### Option 2: Develop Phase A Features (REST API + Dashboard)
```bash
# See detailed prompt in REFACTOR_PROMPT.md
# Copy Prompt Set 1 and paste into Claude
# Follow along as Claude builds:
# - REST API (15+ endpoints)
# - Web Dashboard (React)
# - Report generation (PDF/HTML)
# - Docker setup
```

### Option 3: Optimize for Your Environment
Edit environment variables:
```bash
export TECHNIEUM_PHASE_TIMEOUT=7200      # 2-hour phases
export TECHNIEUM_THREADS=10              # Scan 10 targets in parallel
export TECHNIEUM_DNSX_THREADS=200        # Fast DNS
export TECHNIEUM_HTTPX_THREADS=200       # Fast HTTP probing
python3 technieum.py -f targets.txt
```

### Option 4: Review the Code
Key files to understand:
```
technieum.py                  # Main orchestrator
├─ Phase execution logic
├─ Threading model
├─ Output parsing setup

db/database.py            # Database operations
├─ Schema definition
├─ Insert operations
├─ Query helpers

modules/01_discovery.sh   # Phase 1 (subdomain finding)
modules/02_intel.sh       # Phase 2 (port scanning)
modules/03_content.sh     # Phase 3 (URL discovery)
modules/04_vuln.sh        # Phase 4 (vuln testing)

parsers/parser.py         # Output parsing
├─ Subdomain parsers
├─ Port parsers
├─ Vulnerability parsers
```

---

## Common Commands Reference

```bash
# SCANNING
python3 technieum.py -t example.com              # Scan all phases
python3 technieum.py -t example.com -p 1,2      # Only phases 1-2
python3 technieum.py -f targets.txt -T 10       # Parallel scan
python3 technieum.py -t example.com -o custom_dir  # Custom output

# QUERYING
python3 query.py --list                       # List all targets
python3 query.py -t example.com --summary     # Overview
python3 query.py -t example.com --subdomains  # Show subdomains
python3 query.py -t example.com --vulns       # Show vulnerabilities
python3 query.py -t example.com --urls        # Show URLs found

# EXPORTING
python3 query.py -t example.com --export subdomains -o subs.csv
python3 query.py -t example.com --export vulnerabilities -o vulns.csv
python3 query.py -t example.com --export all -o full.csv

# DATABASE
sqlite3 technieum.db "SELECT COUNT(*) FROM subdomains"  # Direct queries
sqlite3 technieum.db "SELECT * FROM vulnerabilities WHERE severity='critical'"
```

---

## Understanding the 4 Phases

### Phase 1: Discovery (30-45 min)
- Finds thousands of subdomains
- Resolves DNS
- Checks which ones respond to HTTP
- **Output:** `all_subdomains.txt`, `alive_hosts.txt`

### Phase 2: Intelligence (30-60 min)
- Port scanning (quick RustScan + deep Nmap)
- OSINT (Shodan, Censys)
- Leak detection (gitleaks)
- **Output:** `ports.xml`, `leaks.json`, service versions

### Phase 3: Content Discovery (45-120 min)
- Archive crawling (Wayback, GAU)
- Directory brute-forcing
- JavaScript analysis
- **Output:** `all_urls.txt`, 10k-100k URLs found

### Phase 4: Vulnerability Scanning (60-180 min)
- Template-based scanning (Nuclei)
- Web app testing (XSS, SQLi)
- SSL/TLS analysis
- **Output:** `vulnerabilities.json`, list of findings

---

## File Structure

```
project/
├── README.md                    ← Start here
├── DOCUMENTATION.md             ← Full guide (8000+ words)
├── DOCUMENTATION_INDEX.md       ← Quick reference
├── DOCUMENTATION_UPDATE.md      ← What's new
├── REFACTOR_PROMPT.md           ← Development prompts
│
├── technieum.py                    ← Main tool
├── query.py                     ← Query/export tool
├── config.yaml                  ← Configuration (not used yet)
├── requirements.txt             ← Python packages
│
├── db/database.py               ← Database manager
├── modules/                     ← 4 phase scripts
│   ├── 01_discovery.sh
│   ├── 02_intel.sh
│   ├── 03_content.sh
│   └── 04_vuln.sh
├── parsers/parser.py            ← Output parsing
│
├── output/                      ← Scan results (auto-created)
│   └── example_com/
│       ├── phase1_discovery/
│       ├── phase2_intel/
│       ├── phase3_content/
│       └── phase4_vulnscan/
│
└── technieum.db                    ← SQLite database (auto-created)
```

---

## FAQ

**Q: How long does a full scan take?**
A: 2-5 hours depending on domain size. Break into phases if needed.

**Q: Can I stop and resume scans?**
A: Yes, it tracks progress. Run again to continue where it left off.

**Q: What if tools aren't installed?**
A: Install with `sudo bash install.sh`, or re-run without those tools.

**Q: What's the difference between current and future versions?**
A: Current = CLI tool. Future = REST API, Web UI, scheduling, alerts, enterprise features.

**Q: How do I use this for my company?**
A: Install, run on your domains, get reports showing asset inventory + vulnerabilities.

**Q: Can I modify tools or add custom tools?**
A: Yes, edit modules/*.sh scripts. Phase D will have a plugin system.

**Q: Is this production-ready?**
A: CLI tool: YES. API/Dashboard: Not yet (coming Phase A ~April 2026).

---

## Next Steps - Pick One

1. **Immediately Use It**
   - Scan your domains
   - Export reports
   - Find vulnerabilities to fix

2. **Contribute to Development**
   - Read [REFACTOR_PROMPT.md](REFACTOR_PROMPT.md)
   - Use prompts with Claude to build Phase A
   - Build REST API and Web Dashboard

3. **Understand the Code**
   - Read architecture in DOCUMENTATION.md
   - Study Phase implementations
   - Review parser logic

4. **Share with Team**
   - Show them DOCUMENTATION.md
   - Demonstrate live scanning
   - Export sample reports

---

## Support

- **Questions?** Check [DOCUMENTATION.md](DOCUMENTATION.md) sections
- **Bugs?** Check Troubleshooting section
- **Ideas?** Review [REFACTOR_PROMPT.md](REFACTOR_PROMPT.md) roadmap
- **Want to build Phase A?** Start with Prompt Set 1

---

## Key Takeaways

1. **Technieum finds your attack surface** - all subdomains, URLs, ports, vulnerabilities
2. **Currently a CLI tool** - powerful but requires command-line knowledge
3. **Clear roadmap for improvement** - REST API, Web UI, scheduling, enterprise features planned
4. **Orchestrates 50+ tools** - maximum coverage through tool redundancy
5. **Database-driven** - results stay in queryable database, not lost in logs
6. **Open-source** - MIT license, can be extended
7. **Real product** - works today, built for real security teams

---

## Time Estimate to Learn

- **5 min:** Understand what Technieum does
- **5 min:** Install and run first scan
- **10 min:** Query results and export
- **10 min:** Read full documentation
- **Total:** ~30 minutes to full understanding

---

**Start with:** `python3 technieum.py -t example.com`  
**Then read:** [DOCUMENTATION.md](DOCUMENTATION.md)  
**For development:** [REFACTOR_PROMPT.md](REFACTOR_PROMPT.md)

---

**Happy scanning! 🚀**
