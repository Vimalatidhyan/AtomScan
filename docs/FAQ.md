# Frequently Asked Questions

Quick answers to common questions about Technieum.

---

## General Questions

### What is Technieum?
Technieum is an automated attack surface mapping tool. Give it a domain name, and it automatically discovers all your subdomains, validates which are live, maps accessible web content, and scans for vulnerabilities. It orchestrates 50+ specialized security tools into a single unified workflow.

### Who should use Technieum?
- Security professionals conducting assessments
- Penetration testers doing reconnaissance
- Bug bounty hunters finding vulnerabilities
- Organizations monitoring their own digital footprint
- Teams needing fast attack surface mapping

### How much does it cost?
Technieum is free and open source (MIT License). You just need to install it on your own infrastructure.

### Do I need special skills to use it?
No. Basic command-line skills will do. We've designed it to be accessible to security professionals of any experience level.

### Is it legal to use?
Yes. Technieum is a reconnaissance tool. Like any security tool, it's legal when used:
- On systems you own
- On systems you have permission to test
- In compliance with local laws

Always get written permission before testing any system you don't own.

---

## Installation & Setup

### How do I install Technieum?
```bash
bash setup.sh
pip3 install -r requirements.txt
```

This installs Python dependencies and all 50+ security tools. Takes 15-30 minutes depending on your internet speed.

### What are the system requirements?
- Python 3.11 or higher
- Linux or macOS (Windows via WSL)
- 2GB disk space minimum
- Internet connection
- About 1-2 hours for initial tool installation

### How long does installation take?
Typically 20-30 minutes depending on internet connection and your system. Tool downloads are largest part.

### Can I run it on Windows?
Technieum is designed for Linux/macOS. Windows users can use Windows Subsystem for Linux (WSL) to run it.

### Which API keys do I need?
Most tools work without API keys. Optional (but helpful) keys include:
- Shodan (better port data)
- Hunter.io (email finding)
- VirusTotal (file analysis)

All are optional. Refer to config.yaml for setup.

### Does installation require sudo/root?
Some tools require elevated privileges. The setup script will prompt you when needed.

---

## Running Scans

### How do I run my first scan?
```bash
python3 technieum.py -t example.com
```

This scans the target completely (all 4 phases). Takes 2-6 hours depending on target size.

### How long do scans take?
- Small target (10-50 subdomains): 1-2 hours
- Medium target (50-200 subdomains): 2-4 hours
- Large target (200+ subdomains): 4-8 hours

Depends on how many live hosts, URLs, and vulnerabilities exist.

### Can I scan multiple targets at once?
Yes:
```bash
python3 technieum.py -t example.com,other.com,third.com
```

Or from file:
```bash
python3 technieum.py -t targets.txt
```

### Can I interrupt a scan?
Yes, press Ctrl+C. Your progress is saved. Resume with:
```bash
python3 technieum.py -t example.com --resume
```

### Can I run only certain phases?
Yes. Phase 1 = discovery only, Phase 2 = validation, etc:
```bash
python3 technieum.py -t example.com --phases 1
```

### Does the scan use a lot of bandwidth?
Moderate amounts. Mostly downloading public data (certificates, DNS records, web crawling). Budget 100MB-1GB per target depending on size.

### Can scans run in the background?
Yes. Use nohup to keep running even if terminal closes:
```bash
nohup python3 technieum.py -t example.com &
```

---

## Understanding Results

### Where are results stored?
In two places:
1. **Database:** `db/results.db` (SQLite) - Searchable, structured
2. **Files:** `output/{target}/` - Raw tool outputs

Query the database to get formatted results:
```bash
python3 query.py -t example.com --summary
```

### How do I get results?
Query tool gives you formatted output:
```bash
python3 query.py -t example.com --subdomains
python3 query.py -t example.com --vulnerabilities
python3 query.py -t example.com --export csv
```

### What data is collected?
- Subdomains
- Live hosts
- Open ports
- Web endpoints
- Vulnerabilities
- Secrets/credentials leaks
- Technology fingerprints
- Service versions

### How accurate are the results?
Very. Technieum uses established tools (Nmap, Nuclei, etc.) that are industry-standard. False positives are rare. However:
- Some tools may timeout on large targets
- Network issues may cause missed data
- API rate limits may affect some tools

### Can I export results?
Yes, multiple formats:
```bash
python3 query.py -t example.com --export csv
python3 query.py -t example.com --export json
python3 query.py -t example.com --export all
```

### How do I share results with my team?
Export as CSV or JSON:
```bash
python3 query.py -t example.com --export csv > report.csv
```

Then share the file. Phase A will add proper report generation.

---

## Database & Storage

### What's the database for?
Instead of scattered log files, all results go into a SQLite database. This allows:
- Searchable queries
- Relationship mapping
- Easy export
- Deduplication
- Analytics

### Can I query the database directly?
Yes:
```bash
sqlite3 db/results.db
SELECT * FROM subdomains WHERE target='example.com';
```

See QUICK_REFERENCE.md for more examples.

### How big does the database get?
Typically 1-5MB per scanned target, depending on findings size. A database with 20 targets might be 50-100MB.

### Should I back up the database?
Yes. This is your only copy of scan results:
```bash
cp db/results.db db/results.db.backup
```

Consider backing up regularly.

### Can I delete old scans?
Yes. You can delete from the database or just move the output folder:
```bash
rm -rf output/old_target/
# Data remains in database; use SQL DELETE to remove
```

### How do I migrate the database?
Phase D will add PostgreSQL support. For now, SQLite only. To move databases:
```bash
cp db/results.db /new/location/results.db
```

---

## Tools & Configuration

### Which tools are included?
50+ tools across discovery, validation, content discovery, and vulnerability scanning. See TOOLS.md or QUICK_REFERENCE.md.

### Can I add my own tools?
Yes. Edit modules (01_discovery.sh, 02_intel.sh, etc.) to add tools. You may need to write a parser for the output.

### How do I customize which tools run?
Edit config.yaml:
```yaml
tools:
  discovery:
    - subfinder
    - amass
```

Only listed tools run.

### What if a tool isn't installed?
The setup script installs all 50+. If missing, manually install:
```bash
apt-get install (tool-name)  # Linux
brew install (tool-name)      # macOS
```

Then verify:
```bash
which tool-name
```

### Can I adjust tool timeouts?
Yes, in config.yaml:
```yaml
targets:
  timeout: 300  # Seconds per tool
```

### How do threads work?
Config value controls parallel tool execution:
```yaml
targets:
  threads: 10  # Run up to 10 tools in parallel
```

Higher = faster but uses more CPU/RAM. Default 10 is safe.

---

## Troubleshooting

### Scan seems stuck
Check if tools are running:
```bash
ps aux | grep -E "subfinder|nmap|nuclei"
```

If frozen, interrupt and resume:
```bash
Ctrl+C
python3 technieum.py -t example.com --resume
```

### Getting "command not found" errors
Tool isn't installed:
```bash
bash setup.sh  # Reinstall
```

Or manually:
```bash
apt-get install (tool-name)
```

### Query returns no results
Database might be empty:
```bash
# Check if data was collected
ls -la output/example.com/
sqlite3 db/results.db "SELECT COUNT(*) FROM subdomains;"
```

If empty, scan didn't complete. Check logs:
```bash
tail -f logs/technieum.log
```

### API key isn't working
Check format in config.yaml:
```yaml
apis:
  shodan: "your-actual-key-here"  # Must be in quotes
```

Test key manually:
```bash
# Example for Shodan
curl -s "https://api.shodan.io/shodan/host/8.8.8.8?key=YOUR_KEY"
```

### Getting permission denied errors
Some tools need elevated access:
```bash
sudo python3 technieum.py -t example.com
```

Or give user permissions:
```bash
sudo usermod -aG docker $USER
```

### Network connection errors
Check your internet:
```bash
ping google.com
```

Some tools fail gracefully on network issues. Try resuming:
```bash
python3 technieum.py -t example.com --resume
```

For more troubleshooting, see TROUBLESHOOTING.md.

---

## Features & Roadmap

### What's the 4-phase approach?
**Phase 1:** Discover all subdomains  
**Phase 2:** Validate which are live  
**Phase 3:** Map accessible web content  
**Phase 4:** Scan for vulnerabilities  

Each phase feeds results to the next.

### What's planned for Phase A?
- REST API (programmatic access)
- Web dashboard (browser UI)
- Report generation (PDF/HTML)
- Docker support (easy deployment)

### When is Phase A coming?
Estimated Q2 2026 (2-3 weeks of dedicated development).

### Will there be more phases?
Yes. Phase B will add scheduling and alerts. Phase C adds enterprise features. Phase D adds distributed scaling.

### Can I contribute features?
Yes. Check the contributing guide. Custom tools and parsers are welcome.

---

## Security & Privacy

### Is my data secure?
Yes. Everything stays on your machine:
- Results stored locally
- No cloud uploads
- No "phone home"
- No external dependencies after download

### Can I use this legally?
Yes, for authorized testing only:
- Your own infrastructure: Always legal
- Client testing: Requires written permission
- Bug bounties: Follow platform rules
- Penetration testing: Requires scope agreement

### Does it leave traces?
Yes, the tools perform active scanning. Target will see:
- DNS queries for subdomains
- HTTP requests to find web content
- Port scans (if that phase runs)
- Vulnerability scanning traffic

This is visible in target's logs. Always have authorization.

### Should I use VPN for scanning?
That depends on your assessment scope and authorization. Private testing on your own systems doesn't require VPN. Authorized assessments follow client requirements.

---

## Performance & Optimization

### How can I speed up scans?
1. Increase threads in config.yaml (uses more CPU)
2. Reduce phase timeout values
3. Disable optional tools you don't need
4. Run important phases (1-2) first, skip advanced (4) till later

### How can I reduce resource usage?
1. Lower thread count in config.yaml
2. Run phases individually instead of all at once
3. Disable memory-intensive tools
4. Close other applications

### What's the minimum hardware?
- RAM: 4GB (8GB recommended)
- CPU: 2 cores (4+ better)
- Disk: 5GB minimum (10GB+ recommended)
- Network: Stable connection

### Should I dedicate a machine to scanning?
For heavy use, yes. Set up a dedicated scanner:
- Old laptop or VM works fine
- Run scans in background
- Keep local copy of results

Phase D will add distributed workers for true scaling.

---

## Comparing to Other Tools

### How is Technieum different?
- **Comprehensive:** Entire reconnaissance workflow in one tool
- **Multi-tool:** Uses best-of-breed for each phase
- **Automated:** Run all 4 phases with one command
- **Integrated:** Results flow between phases intelligently
- **Free & Open:** Complete source code, MIT license

### How does it compare to Metasploit?
Different tools for different jobs:
- **Metasploit:** Exploitation framework (attacks systems)
- **Technieum:** Reconnaissance platform (maps systems)

Technieum feeds into Metasploit – use together for complete assessment.

### Can Technieum replace Shodan?
No, different purposes:
- **Shodan:** Internet-wide search engine for devices
- **Technieum:** Deep analysis of specific targets

Technieum can use Shodan as a data source (if you have API key).

---

## Getting Help

### Where do I find documentation?
- README.md - Full overview
- QUICK_REFERENCE.md - Commands and syntax
- TROUBLESHOOTING.md - Problem solving
- This FAQ - Fast answers
- TOOLS.md - Details on each tool
- PHASES.md - How the 4 phases work
- USE_CASES.md - Real examples

### How do I report bugs?
Check TROUBLESHOOTING.md first. For actual bugs, include:
- Error message
- Command you ran
- System info (OS, Python version)
- Relevant logs from `logs/` folder

### How do I request features?
Phase A, B, C, D roadmaps already exist in documentation. For custom features:
- Check if it's in the roadmap
- See if you can add it as a custom tool
- Follow contributing guidelines

---

## Quick Decision Tree

**"Is Technieum right for me?"**
```
Do you need to assess an organization's attack surface?
  → Yes: Technieum is perfect
  → No: Different tool may be better

Do you have basic command-line skills?
  → Yes: You can use Technieum
  → Unsure: See QUICKSTART in README.md

Do you have authorization to test targets?
  → Yes: You're good to go
  → No: Get written permission first
```

---

**Still have questions? Check README.md, TROUBLESHOOTING.md, or QUICK_REFERENCE.md for more details.**
