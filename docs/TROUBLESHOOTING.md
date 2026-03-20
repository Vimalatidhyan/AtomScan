# Troubleshooting Guide

Solutions for common problems.

---

## Installation Issues

### Error: "Python 3.11 not found"
**Problem:** System has older Python version.

**Solutions:**
```bash
# Check Python version
python3 --version

# Install Python 3.11+ 
# Ubuntu/Debian:
sudo apt-get install python3.11

# macOS:
brew install python@3.11

# Then use python3.11 specifically:
python3.11 technieum.py -t example.com
```

### Error: "bash setup.sh: permission denied"
**Problem:** Script not executable.

**Solution:**
```bash
chmod +x setup.sh
bash setup.sh
```

### Error: "requirements.txt - No module named 'xxx'"
**Problem:** Python package didn't install correctly.

**Solution:**
```bash
# Reinstall packages
pip3 install -r requirements.txt --force-reinstall

# Or install specific package
pip3 install package-name
```

### Error: "Command not found" for tools
**Problem:** Security tool didn't install properly.

**Solution:**
```bash
# Reinstall all tools
bash setup.sh

# Check if tool exists
which subfinder
which nmap
which nuclei

# Manual install if needed
# Ubuntu/Debian:
sudo apt-get install tool-name

# macOS:
brew install tool-name
```

### Error: Various warnings during setup
**Problem:** Normal – expected in heterogeneous environments.

**Solution:** These are usually non-fatal. Scan will proceed. Check actual errors, not warnings.

---

## Running Scans

### Scan Hangs/Seems Stuck
**Problem:** Scan running but not outputting anything.

**Solutions:**
```bash
# 1. Check if tools are actually running
ps aux | grep -E "subfinder|nmap|nuclei"

# 2. Check log file
tail -f logs/technieum.log

# 3. If truly stuck, interrupt gracefully
Ctrl+C

# 4. Resume where you left off
python3 technieum.py -t example.com --resume
```

**Why it happens:** Large targets or slow tools can take hours. Check logs.

### Error: "target not found" or "empty results"
**Problem:** Scan ran but found nothing.

**Possible causes:**
1. Domain name is invalid
2. DNS doesn't resolve
3. No subdomains exist
4. Network connectivity issue

**Diagnosis:**
```bash
# 1. Verify domain is real
nslookup example.com
dig example.com

# 2. Check output files
ls -la output/example.com/phase1_discovery/

# 3. Check database
sqlite3 db/results.db "SELECT * FROM subdomains WHERE target='example.com';"

# 4. Check logs
tail -100 logs/technieum.log | grep example.com
```

**Solutions:**
```bash
# If domain doesn't resolve, check spelling
python3 technieum.py -t yourdomain.com  # Not example.com

# If network issue
ping google.com
# Fix network then resume
python3 technieum.py -t example.com --resume

# If DNS issue
# Try with forced nameserver
python3 technieum.py -t example.com --nameserver 8.8.8.8
```

### Error: "too many open files"
**Problem:** System running out of file descriptors.

**Solution:**
```bash
# Increase file limit
ulimit -n 4096

# Or reduce threads in config.yaml:
# Change threads: 10 to threads: 5
```

### Error: "out of memory"
**Problem:** System running out of RAM during scan.

**Solutions:**
```bash
# 1. Close other applications
killall chrome firefox thunderbird  # Examples

# 2. Reduce threads
# Edit config.yaml: threads: 10 → threads: 5

# 3. Reduce timeout
# Edit config.yaml: timeout: 300 → timeout: 60

# 4. Scan with less aggressive settings
python3 technieum.py -t example.com --quick
```

### Error: Network/DNS errors during scan
**Problem:** Tools getting DNS or connection errors.

**Causes:** Network issues, DNS timeouts, ISP blocking.

**Solutions:**
```bash
# Check network
ping google.com
curl -I https://google.com

# Check DNS
nslookup 1.1.1.1
# If fails, your DNS is down

# Try alternate DNS
# Edit config.yaml or use environment variable:
export DNS_RESOLVER=8.8.8.8

# Resume scan
python3 technieum.py -t example.com --resume
```

### Error: Specific tool fails repeatedly
**Problem:** One tool keeps failing, blocks scan.

**Solution:**
```bash
# Disable that tool in config.yaml
# Modify modules/XX_phase.sh to comment out the tool
# Syntax usually: # command-here

# Or edit config.yaml to remove tool from list:
tools:
  discovery:
    - subfinder     # This one works
    # - problematic-tool  # Comment out this one
    - assetfinder

# Retry scan
python3 technieum.py -t example.com --resume
```

### Error: API key authentication failures
**Problem:** Tool with API key fails to authenticate.

**Checks:**
```bash
# 1. Verify key is in config.yaml correctly
cat config.yaml | grep -A3 "apis:"

# Format should be:
# apis:
#   shodan: "your-actual-key-in-quotes"

# 2. Verify key is valid by testing manually
# For Shodan example:
curl -s "https://api.shodan.io/shodan/host/8.8.8.8?key=YOUR_KEY" | head

# If error, key is invalid

# 3. Get new key and update config
nano config.yaml  # Edit and save

# 4. Retry
python3 technieum.py -t example.com --resume
```

---

## Query & Results

### Query Returns No Results
**Problem:** Query runs but shows no data.

**Causes:** Database empty, scan didn't complete, targeting error.

**Diagnosis:**
```bash
# Check if data exists in database
sqlite3 db/results.db "SELECT COUNT(*) as total FROM subdomains WHERE target='example.com';"

# Check if output files exist
ls -la output/example.com/phase1_discovery/

# Check scan status
sqlite3 db/results.db "SELECT target, phase, status FROM scan_progress WHERE target='example.com';"
```

**Solutions:**
```bash
# If count is 0, scan didn't complete
# Resume:
python3 technieum.py -t example.com --resume

# Make sure target name matches exactly
# Case sensitive!
python3 query.py -t Example.com  # Wrong (different case)
python3 query.py -t example.com  # Correct
```

### Export to CSV Not Working
**Problem:** CSV export fails or creates empty file.

**Solution:**
```bash
# 1. Try explicit path
python3 query.py -t example.com --subdomains --export csv > results.csv

# 2. Check if data exists first
python3 query.py -t example.com --summary

# 3. If export still fails, try different format
python3 query.py -t example.com --export json

# 4. Check permissions on output directory
ls -la results.csv
chmod 644 results.csv
```

### Can't Find Specific Vulnerability
**Problem:** You know it exists but query doesn't show it.

**Causes:** Wrong keyword, wrong severity level, tool didn't find it, parsing issue.

**Diagnosis:**
```bash
# Query database directly
sqlite3 db/results.db
SELECT * FROM vulnerabilities WHERE target='example.com' AND notes LIKE '%keyword%';

# Or list all vulnerabilities
SELECT DISTINCT vulnerability_type FROM vulnerabilities WHERE target='example.com';
```

**Solutions:**
```bash
# Use broadest query first
python3 query.py -t example.com --vulnerabilities

# Then filter manually or check spreadsheet
python3 query.py -t example.com --export csv | grep keyword

# Specific tool's vulnerability:
python3 query.py -t example.com --tool nuclei
```

---

## Database Issues

### Database Locked Error
**Problem:** "database is locked" error while querying.

**Cause:** Another process accessing database while you query.

**Solutions:**
```bash
# 1. Wait for scan to complete
ps aux | grep technieum.py
# If running, wait for it to finish

# 2. Or use --timeout to force unlock
sqlite3 db/results.db ".timeout 30000"

# 3. If persistently locked, restart system
```

### Database Corruption
**Problem:** SQLite errors, can't query, "database disk image is malformed".

**Solution:**
```bash
# 1. Check integrity
sqlite3 db/results.db "PRAGMA integrity_check;"

# 2. If corrupted, try to recover
sqlite3 db/results.db ".dump" > results_dump.sql

# 3. Restore from backup if you have one
cp db/results.db.backup db/results.db

# 4. If no backup, current data is lost
# Better luck next time – back up regularly!
```

### Database Getting Too Large
**Problem:** `db/results.db` consuming lots of disk space.

**Solutions:**
```bash
# 1. Check size
ls -lh db/results.db

# 2. Delete old results
sqlite3 db/results.db
DELETE FROM subdomains WHERE target='old-target.com';
DELETE FROM scan_progress WHERE target='old-target.com';
-- (Repeat for other tables)
VACUUM;  # Reclaim space

# 3. Or archive old results
cp db/results.db db/results_archive_2026-01-01.db
# Then delete old data from active database

# 4. Or split database
# Keep last 10 targets, archive rest
```

---

## Performance & Resource Issues

### Scan Running Very Slowly
**Problem:** Scan is progressing but extremely slowly.

**Causes:** System overloaded, network slow, tool timeouts too long.

**Solutions:**
```bash
# 1. Check system resources
top  # Press Ctrl+C to exit
# Look for CPU at 100% or memory full

# 2. Close unnecessary applications
killall chrome firefox  # Examples

# 3. Reduce thread count in config.yaml
# Change: threads: 10
# To: threads: 5

# 4. Reduce timeout values
# Change: timeout: 300 (5 minutes)
# To: timeout: 60 (1 minute)

# 5. Check network speed
speedtest  # If available, or speedtest-cli

# 6. Reduce scan scope
# Run only phases 1&2 first (faster)
python3 technieum.py -t example.com --phases 1,2
```

### High CPU Usage
**Problem:** Scan consuming 80-100% CPU constantly.

**Expected behavior:** Some tools are CPU-intensive.

**If excessive:**
```bash
# 1. Identify which tool
ps aux | sort -k3 -nr | head
# Look for nmap, nuclei, etc using most CPU

# 2. Reduce parallelization
# Edit config.yaml: threads: 10 → threads: 2

# 3. Increase tool timeouts to reduce retries
# Edit config.yaml: timeout: 300 

# 4. Run phases sequentially (one at a time)
python3 technieum.py -t example.com --phases 1
# Wait for completion
python3 technieum.py -t example.com --phases 2
# etc.
```

### High Disk I/O
**Problem:** Disk constantly reading/writing, seems slow.

**Causes:** Large scans writing tons of data, database operations.

**Solutions:**
```bash
# 1. Check disk space
df -h
# If <10% free, may slow down

# 2. Stop other disk-intensive processes
# Close backup tools, video encoding, downloads

# 3. Reduce output verbosity
# Edit config.yaml: verbose: true → verbose: false

# 4. Run scan in background and monitor
nohup python3 technieum.py -t example.com > scan.log 2>&1 &
```

---

## Authorization & Permission Issues

### Error: "Permission Denied"
**Problem:** Script or file permission error.

**Solution:**
```bash
# For scripts
chmod +x program.sh

# For files created by scan
chmod 644 file.txt

# For database (if issues)
chmod 666 db/results.db

# For directories
chmod 755 output/
```

### Error: "sudo required"
**Problem:** Some tools need elevated privileges.

**Solution:**
```bash
# Run entire scan with sudo
sudo python3 technieum.py -t example.com

# Or give current user permissions
# For Nmap:
sudo setcap cap_net_raw=ep /usr/bin/nmap

# For Docker (if Phase A installed):
sudo usermod -aG docker $USER
```

---

## Logging & Diagnostics

### Check Logs
**Problem:** Trying to see what happened during scan.

**Solution:**
```bash
# Main log
tail -100 logs/technieum.log

# Follow log in real-time while scanning
tail -f logs/technieum.log

# Search log for errors
grep -i error logs/technieum.log

# Search for specific target
grep example.com logs/technieum.log

# Full scan history
cat logs/technieum.log | grep "Scan started"
```

### Enable Debug Mode
**Problem:** Need detailed diagnostic output.

**Solution:**
```bash
# Run with debug flag
python3 technieum.py -t example.com --debug

# Or verbose
python3 technieum.py -t example.com --verbose

# Output goes to logs/technieum.log
tail -f logs/technieum.log
```

### Get Support
**When seeking help, include:**
1. Full error message
2. Command you ran
3. Output of: `python3 --version`
4. Output of: `uname -a`
5. Relevant log excerpts from `logs/technieum.log`

---

## Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| `command not found: subfinder` | Tool not installed | `bash setup.sh` |
| `ModuleNotFoundError: fastapi` | Python package missing | `pip3 install -r requirements.txt` |
| `sqlite3.OperationalError: database is locked` | Scan still running | Wait or restart |
| `too many open files` | File descriptor limit | `ulimit -n 4096` |
| `out of memory` | System RAM full | Close apps, reduce threads |
| `Connection refused` | Network/tools issue | Check network, retry |
| `DNS lookup failed` | Network/DNS issue | Check DNS, try again |
| `Invalid API key` | Wrong credent in config | Update `config.yaml` |
| `Target not found` | Domain doesn't exist | Verify domain name |
| `No results` | Scan incomplete | Use `--resume` |

---

## Getting More Help

| Resource | When to Use |
|----------|------------|
| **FAQ.md** | Quick answers |
| **QUICK_REFERENCE.md** | Command syntax |
| **README.md** | General understanding |
| **Logs** | Detailed error info |
| **SQLite database** | Raw data inspection |

---

**Still stuck? Check FAQ.md for questions, README.md for overview, or try the command reference.**
