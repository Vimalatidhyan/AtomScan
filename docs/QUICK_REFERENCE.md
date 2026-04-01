# Quick Reference: Commands & Syntax

Fast lookup for common Technieum commands. For full details, see README.md.

---

## Basic Scanning

### Scan a Single Target
```bash
python3 technieum.py -t example.com
```
Runs all 4 phases automatically.

### Scan Multiple Targets
```bash
python3 technieum.py -t example.com,other.com,third.com
python3 technieum.py -t targets.txt  # One per line
```

### Run Specific Phases Only
```bash
python3 technieum.py -t example.com --phases 1
python3 technieum.py -t example.com --phases 1,2
python3 technieum.py -t example.com --phases 1-3
```

### Resume Interrupted Scan
```bash
python3 technieum.py -t example.com --resume
```

---

## Querying Results

### Summary View
```bash
python3 query.py -t example.com --summary
```
High-level overview of findings.

### List Subdomains
```bash
python3 query.py -t example.com --subdomains
python3 query.py -t example.com --subdomains --live-only
```

### List Open Ports
```bash
python3 query.py -t example.com --ports
python3 query.py -t example.com --port 443  # Specific port
```

### List All URLs
```bash
python3 query.py -t example.com --urls
```

### List Vulnerabilities
```bash
python3 query.py -t example.com --vulnerabilities
python3 query.py -t example.com --critical  # Critical only
```

### List Secrets/Leaks
```bash
python3 query.py -t example.com --secrets
```

---

## Exporting Data

### Export to CSV
```bash
python3 query.py -t example.com --export csv
python3 query.py -t example.com --subdomains --export csv > subdomains.csv
```

### Export to JSON
```bash
python3 query.py -t example.com --export json
```

### Export All
```bash
python3 query.py -t example.com --export all
# Creates CSV files for each data type
```

---

## Advanced Queries

### Search by Keyword
```bash
python3 query.py -t example.com --keyword "api"
python3 query.py -t example.com --keyword "admin"
```

### Filter by Status
```bash
python3 query.py -t example.com --status active
python3 query.py -t example.com --status dead
```

### Specific Server
```bash
python3 query.py -t example.com --host api.example.com
```

### Specific Port
```bash
python3 query.py -t example.com --port 8080
python3 query.py -t example.com --port 443,8443
```

### Vulnerability Severity
```bash
python3 query.py -t example.com --severity critical
python3 query.py -t example.com --severity high,critical
```

---

## Database Queries

Access the SQLite database directly:

```bash
# Open database
sqlite3 db/results.db

# List all tables
.tables

# See table structure
.schema subdomains

# Query subdomains
SELECT * FROM subdomains WHERE target='example.com';

# Count findings
SELECT COUNT(*) FROM vulnerabilities WHERE target='example.com' AND severity='critical';

# Find all URLs
SELECT url FROM urls WHERE target='example.com' LIMIT 20;

# Export to CSV
.mode csv
.output results.csv
SELECT * FROM subdomains WHERE target='example.com';
.output stdout
```

---

## Configuration

Edit `config.yaml`:

```yaml
# Target configuration
targets:
  threads: 10  # Parallel execution threads
  timeout: 300  # Seconds per tool

# Phase toggles
phases:
  discovery: true
  intelligence: true
  content: true
  vulnerability: true

# Tool selection
tools:
  discovery:
    - subfinder
    - amass
    - assetfinder
  intelligence:
    - nmap
    - httpx

# API keys
apis:
  shodan: your-key-here
  hunter: your-key-here
  virustotal: your-key-here

# Output settings
output:
  format: json  # json, csv, text
  save_intermediate: true
```

---

## Setup & Installation

### Quick Install
```bash
bash setup.sh
pip3 install -r requirements.txt
```

### Manual Setup
```bash
# 1. Install Python (3.11+)
# 2. Install system dependencies (curl, git, etc.)
# 3. Run setup script
bash setup.sh

# 4. Install Python packages
pip3 install -r requirements.txt

# 5. Configure API keys
nano config.yaml

# 6. Test installation
python3 technieum.py -t example.com --phases 1
```

---

## Common Workflows

### Quick Assessment
```bash
# Scan and get summary
python3 technieum.py -t example.com
python3 query.py -t example.com --summary --vulnerabilities --critical
```

### Detailed Report
```bash
# Run full scan
python3 technieum.py -t example.com

# Export everything
python3 query.py -t example.com --export all

# Get specific reports
python3 query.py -t example.com --subdomains --export csv > subs.csv
python3 query.py -t example.com --vulnerabilities --export csv > vulns.csv
```

### Batch Scanning
```bash
# Create targets.txt with one domain per line
example.com
other.com
third.com

# Scan all
python3 technieum.py -t targets.txt

# Report on each
for target in $(cat targets.txt); do
  echo "=== $target ==="
  python3 query.py -t $target --summary
done
```

### Monitor for Changes
```bash
# Run initial scan
python3 technieum.py -t example.com
python3 query.py -t example.com --export all > baseline.csv

# Run again later
python3 technieum.py -t example.com
python3 query.py -t example.com --export all > current.csv

# Compare
diff baseline.csv current.csv
```

---

## Troubleshooting Commands

### Check Tool Installation
```bash
# Test if tools are installed
which subfinder
which nmap
which nuclei

# List installed tools
ls /usr/local/bin | grep -E "subfinder|nmap|nuclei"
```

### View Scan Progress
```bash
# Watch log output
tail -f logs/technieum.log

# Check current phase
ps aux | grep technieum.py
```

### Database Health Check
```bash
# Open database
sqlite3 db/results.db

# Check table sizes
SELECT name, COUNT(*) FROM subdomains GROUP BY target;

# Verify data integrity
PRAGMA integrity_check;

# Export specific scan
.mode csv
SELECT * FROM subdomains WHERE target='example.com';
```

### Debug Mode
```bash
# Run with verbose output
python3 technieum.py -t example.com --verbose

# Enable debug logging
python3 technieum.py -t example.com --debug
```

---

## File Locations

```
Results:          output/{target}/{phase}*/
Database:         db/results.db
Configuration:    config.yaml
Logs:             logs/
Main script:      technieum.py
Query script:     query.py
Modules:          modules/
Parsers:          parsers/
Documentation:    docs/
```

---

## Getting Help

| Question | Answer |
|----------|--------|
| How do I use Technieum? | See README.md |
| What tools are included? | See TOOLS.md or `ls modules/` |
| Something's broken | See TROUBLESHOOTING.md |
| Common issues | See FAQ.md |
| Real examples | See USE_CASES.md |

---

## Common Issues Quick Fixes

### "Tool not found" error
```bash
# Reinstall
bash setup.sh

# Check PATH
echo $PATH

# Manual install of missing tool
apt-get install (tool-name)  # Linux
brew install (tool-name)      # macOS
```

### Scan hangs
```bash
# Kill and resume
Ctrl+C
python3 technieum.py -t example.com --resume
```

### No results
```bash
# Check database
sqlite3 db/results.db ".tables"

# Check output folder
ls -la output/example.com/

# Run with verbose
python3 technieum.py -t example.com --verbose
```

### API key errors
```bash
# Edit config
nano config.yaml

# Verify key format
# Keys should be in quotes: "your-key-here"
```

---

## Environment Variables

```bash
# Set API keys via environment
export SHODAN_API_KEY="your-key"
export HUNTER_API_KEY="your-key"

# Run scan
python3 technieum.py -t example.com
```

---

## Pro Tips

1. **Parallel Scanning:** Use multiple terminals to scan different targets simultaneously
2. **Target Lists:** Put one domain per line in targets.txt for batch scanning
3. **Regular Scanning:** Set up cron jobs (Phase B will automate this)
4. **Result Backup:** Backup `db/results.db` regularly
5. **Custom Queries:** Write SQL queries for advanced analysis
6. **Export Formats:** CSV is best for Excel, JSON for scripting
7. **Phase Resuming:** Always use `--resume` to pick up where you left off
8. **Staging vs. Production:** Test config changes on non-critical targets first

---

## Statistics & Limits

- **Max targets per run:** Unlimited (system RAM dependent)
- **Max subdomains:** Limited by database size (typically 100K+)
- **Average scan time:** 2-6 hours depending on target size
- **Database size:** Grows ~1-5MB per target scanned
- **Parallel threads:** Default 10, configurable in config.yaml

---

**For detailed information, see README.md**  
**For troubleshooting, see TROUBLESHOOTING.md**  
**For questions, see FAQ.md**
