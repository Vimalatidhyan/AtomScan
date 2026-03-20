# MASTER REFACTORING PROMPT FOR CLAUDE SONNET

> **Copy everything below this line and paste it into a new Claude Sonnet (or Claude Code) session.**

---

## Role

You are a Senior Python/Bash Security Tooling Engineer performing a complete refactoring of the **Technieum** Attack Surface Management framework. You have been given a detailed audit report and must fix every issue identified — bugs, performance bottlenecks, missing features, dead code, and architectural problems.

## Project Location

```
/Users/rejenthompson/Documents/technieum-/kali-linux-asm/
```

## Step 0: Read Everything First

Before writing ANY code, read every one of these files in full. Do not skip any:

```
technieum.py
db/database.py
parsers/parser.py
query.py
modules/01_discovery.sh
modules/02_intel.sh
modules/03_content.sh
modules/04_vuln.sh
config.yaml
requirements.txt
CODE_AUDIT_REFACTORING_SPEC.md
```

The file `CODE_AUDIT_REFACTORING_SPEC.md` is the audit report. It contains the full analysis of every bug and bottleneck. Use it as your source of truth.

---

## What You Must Fix (In Priority Order)

### PRIORITY 1: Critical Bugs (Fix These First)

#### Bug 1 — FFUF Parser Returns Nothing (`parsers/parser.py`, `parse_ffuf` method)

**Problem:** `read_json()` returns a `List`. When the raw JSON file is `{"results": [...]}`, `read_json` returns `[{"results": [...]}]`. The code then does `if 'results' in data` which checks list membership (is the string "results" an element of the list?), which is always `False`. All FFUF brute-force results are silently dropped.

**Fix:** Change `parse_ffuf` to:
```python
def parse_ffuf(self, file_path: str) -> List[Dict[str, str]]:
    """Parse ffuf JSON output"""
    data = self.read_json(file_path)
    results = []
    for item in data:
        # Handle both raw dict and wrapped formats
        entries = item.get('results', []) if isinstance(item, dict) else []
        for entry in entries:
            if 'url' in entry:
                results.append({
                    'url': entry['url'],
                    'source_tool': 'ffuf',
                    'status': str(entry.get('status', ''))
                })
    return results
```

#### Bug 2 — Singleton Ignores db_path (`db/database.py`, `__new__` / `__init__`)

**Problem:** The Singleton `__new__` caches the first instance forever. If `DatabaseManager("scan1.db")` is created, then `DatabaseManager("scan2.db")` is called later, the second path is silently ignored. The `--database` CLI flag is broken.

**Fix:** Remove the Singleton pattern entirely. Delete `_instance`, `_lock`, and `__new__`. Make it a plain class:
```python
class DatabaseManager:
    """Database Manager with WAL mode enabled"""

    def __init__(self, db_path: str = "technieum.db"):
        self.db_path = db_path
        self.local = threading.local()
        self._init_database()
```

#### Bug 3 — Bulk Insert Silently Drops Data (`db/database.py`, `insert_subdomains_bulk`)

**Problem:** `insert_subdomains_bulk` uses `INSERT OR IGNORE` which silently discards conflicting rows. But the single-row `insert_subdomain` uses `ON CONFLICT ... DO UPDATE` which merges data. When Phase 1 parsing calls `insert_subdomains_bulk` with httpx results that set `is_alive=True`, those updates are silently dropped for subdomains already in the DB.

**Fix:** Change `insert_subdomains_bulk` to use the same `ON CONFLICT DO UPDATE` semantics as the single-row method:
```python
def insert_subdomains_bulk(self, target: str, subdomains: List[Dict[str, Any]]) -> None:
    """Bulk insert/update subdomains"""
    conn = self._get_connection()
    conn.execute("BEGIN")
    try:
        for sub in subdomains:
            conn.execute("""
                INSERT INTO subdomains (target, host, ip, is_alive, status_code, source_tools)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(target, host) DO UPDATE SET
                    ip = COALESCE(excluded.ip, ip),
                    is_alive = excluded.is_alive OR is_alive,
                    status_code = COALESCE(excluded.status_code, status_code),
                    source_tools = CASE
                        WHEN source_tools IS NULL THEN excluded.source_tools
                        WHEN excluded.source_tools IS NULL THEN source_tools
                        WHEN source_tools LIKE '%' || excluded.source_tools || '%' THEN source_tools
                        ELSE source_tools || ',' || excluded.source_tools
                    END
            """, (target, sub['host'], sub.get('ip'), int(sub.get('is_alive', False)),
                  sub.get('status_code'), sub.get('source_tool')))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
```

#### Bug 4 — SQL Injection in `query.py` (`export_csv` method)

**Problem:** `f"SELECT * FROM {table} WHERE target = ?"` interpolates the `table` variable directly into SQL. Even though argparse constrains choices, the method itself is injectable if called from other code.

**Fix:** Add a whitelist:
```python
ALLOWED_TABLES = {'subdomains', 'vulnerabilities', 'leaks', 'ports', 'urls'}

def export_csv(self, target: str, table: str, output_file: str):
    if table not in ALLOWED_TABLES:
        print(f"Error: Invalid table name '{table}'")
        return
    # ... rest of method
```

#### Bug 5 — Mutable Default Argument (`technieum.py`, `run` method)

**Problem:** `def run(self, phases: List[int] = [1, 2, 3, 4])` uses a mutable default.

**Fix:**
```python
def run(self, phases: List[int] = None):
    if phases is None:
        phases = [1, 2, 3, 4]
```

#### Bug 6 — `local` Keyword Outside Function (`modules/01_discovery.sh`, line ~372)

**Problem:** The `wait` loop at the bottom of the passive enumeration section uses `local exit_code=$?` outside a function body.

**Fix:** Remove the `local` keyword:
```bash
for pid in "${pids[@]}"; do
    if wait "$pid"; then
        ((TOOLS_SUCCESS++))
    else
        exit_code=$?
        if [ $exit_code -ne 0 ]; then
            ((TOOLS_FAILED++))
        fi
    fi
done
```

---

### PRIORITY 2: Performance — Python Layer

#### Perf 1 — Replace `subprocess.run` with Streaming `Popen` (`technieum.py`, `run_module`)

**Problem:** `subprocess.run(capture_output=True)` blocks for 30-120 minutes per phase, buffering ALL output in memory. The user sees nothing.

**Fix:** Replace with `subprocess.Popen` that streams stdout line-by-line in real time:
```python
def run_module(self, module_script: str, target: str, output_dir: Path, timeout: int | None = None) -> bool:
    script_path = self.modules_dir / module_script
    if not script_path.exists():
        logger.error(f"Module {module_script} not found at {script_path}")
        return False

    logger.info(f"Executing {module_script} for {target}")
    if timeout is None:
        timeout = self.phase_timeout_default

    try:
        process = subprocess.Popen(
            [str(script_path), target, str(output_dir)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        import threading

        def drain_stderr(proc):
            for line in proc.stderr:
                logger.warning(f"[{module_script}] {line.rstrip()}")

        stderr_thread = threading.Thread(target=drain_stderr, args=(process,), daemon=True)
        stderr_thread.start()

        for line in process.stdout:
            print(line, end='')

        process.wait(timeout=timeout)
        stderr_thread.join(timeout=5)

        if process.returncode != 0:
            logger.error(f"Module {module_script} failed with code {process.returncode}")
            return False
        return True

    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        logger.error(f"Module {module_script} timed out after {timeout}s")
        return False
    except Exception as e:
        logger.error(f"Error running {module_script}: {e}")
        return False
```

#### Perf 2 — Batch Database Transactions (`db/database.py`)

**Problem:** `execute()` calls `conn.commit()` after every single statement. 5,000 subdomain inserts = 5,000 fsync calls.

**Fix:**
- Remove `conn.commit()` from the generic `execute()` method.
- Add explicit `BEGIN`/`COMMIT` wrapping inside `executemany()` and all bulk methods.
- Add a dedicated `commit()` method for callers that need it.
- Keep autocommit for single `execute()` calls by checking if a transaction is active.

Actually, the simplest safe approach: keep `execute()` with commit for single-row ops (it's fine for the few single inserts), but fix `executemany()`:
```python
def executemany(self, query: str, params_list: List[tuple]) -> None:
    if not params_list:
        return
    conn = self._get_connection()
    conn.execute("BEGIN")
    try:
        cursor = conn.cursor()
        cursor.executemany(query, params_list)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
```

#### Perf 3 — Consolidate `get_stats()` Into a Single Query (`db/database.py`)

**Problem:** 8 separate `SELECT COUNT(*)` queries.

**Fix:**
```python
def get_stats(self, target: str) -> Dict[str, int]:
    row = self.fetchone("""
        SELECT
            (SELECT COUNT(*) FROM subdomains WHERE target = ?) as subdomains,
            (SELECT COUNT(*) FROM subdomains WHERE target = ? AND is_alive = 1) as alive_hosts,
            (SELECT COUNT(*) FROM urls WHERE target = ?) as urls,
            (SELECT COUNT(*) FROM vulnerabilities WHERE target = ?) as vulnerabilities,
            (SELECT COUNT(*) FROM vulnerabilities WHERE target = ? AND severity = 'critical') as critical_vulns,
            (SELECT COUNT(*) FROM vulnerabilities WHERE target = ? AND severity = 'high') as high_vulns,
            (SELECT COUNT(*) FROM leaks WHERE target = ?) as leaks,
            (SELECT COUNT(*) FROM ports WHERE target = ?) as open_ports
    """, (target, target, target, target, target, target, target, target))
    return dict(row) if row else {
        'subdomains': 0, 'alive_hosts': 0, 'urls': 0, 'vulnerabilities': 0,
        'critical_vulns': 0, 'high_vulns': 0, 'leaks': 0, 'open_ports': 0
    }
```

#### Perf 4 — Pre-Compile Regexes (`parsers/parser.py`)

**Problem:** `re.match(pattern, ...)` recompiles the regex on every call. `extract_domain` and `is_valid_subdomain` are called thousands of times.

**Fix:** Add class-level compiled patterns:
```python
class OutputParser:
    _DOMAIN_RE = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}')
    _SUBDOMAIN_RE = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    _URL_RE = re.compile(r'(https?://[^\s]+)')
    _PROTOCOL_RE = re.compile(r'^https?://')

    @staticmethod
    def extract_domain(text: str) -> Optional[str]:
        text = OutputParser._PROTOCOL_RE.sub('', text)
        match = OutputParser._DOMAIN_RE.match(text)
        return match.group(0) if match else None

    @staticmethod
    def is_valid_subdomain(subdomain: str) -> bool:
        return bool(OutputParser._SUBDOMAIN_RE.match(subdomain))
```

Update all parser methods that use `re.search(r'(https?://[^\s]+)', line)` to use `OutputParser._URL_RE.search(line)` instead.

#### Perf 5 — Streaming File Readers (`parsers/parser.py`)

**Problem:** `read_lines()` loads entire file into a list. `read_json()` reads entire file to a string then parses. Phase 3 URL files can be 500K+ lines.

**Fix:** Add generator-based readers alongside the existing ones:
```python
@staticmethod
def iter_lines(file_path: str):
    """Yield non-empty lines from file without loading all into memory"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    yield stripped
    except Exception as e:
        print(f"Error reading {file_path}: {e}")

@staticmethod
def iter_jsonl(file_path: str):
    """Yield parsed JSON objects from a JSONL file one at a time"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
    except Exception as e:
        print(f"Error reading JSONL {file_path}: {e}")
```

Update parsers that process large files (URL parsers, nuclei parser, subdomain parsers) to use `iter_lines` / `iter_jsonl` instead of `read_lines` / `read_json`. Keep `read_lines` and `read_json` for small files or where the full list is needed.

#### Perf 6 — Deduplicate URL Parsers (`parsers/parser.py`)

**Problem:** `parse_gau`, `parse_waybackurls`, `parse_hakrawler`, `parse_katana` are identical except for the source_tool string.

**Fix:** Replace all 4 with a single method:
```python
def parse_url_list(self, file_path: str, source_tool: str) -> List[Dict[str, str]]:
    """Parse generic URL list (one URL per line)"""
    return [{'url': line, 'source_tool': source_tool}
            for line in self.iter_lines(file_path) if line.startswith('http')]
```

Then add thin wrappers or update `technieum.py` to call `parse_url_list(path, 'gau')` etc. Also update the dynamic dispatch in `parse_phase3_output` to use a mapping:
```python
URL_TOOL_PARSERS = {
    'gau.txt': 'gau',
    'waybackurls.txt': 'waybackurls',
    'hakrawler.txt': 'hakrawler',
    'katana.txt': 'katana',
    'spideyx.txt': 'spideyx',
    'gospider.txt': 'gospider',
}
```

---

### PRIORITY 3: Performance — Bash Layer

#### Bash Perf 1 — Parallelize Phase 2 DNS Resolution (`modules/02_intel.sh`, lines ~199-227)

**Problem:** Sequential `while read` loop with `dig` for each host.

**Fix:** Replace the entire loop with a bulk approach. If `dnsx` is available, use it:
```bash
# Resolve hostnames to IPs in bulk
if command -v dnsx &> /dev/null; then
    log_info "Resolving hostnames via dnsx..."
    cat "$PORTS_DIR/targets_raw.txt" | dnsx -silent -a -resp-only > "$PORTS_DIR/resolved_ips.txt" 2>/dev/null || true
    # Also keep original hostnames that are already IPs
    grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' "$PORTS_DIR/targets_raw.txt" >> "$PORTS_DIR/resolved_ips.txt" 2>/dev/null || true
    sort -u "$PORTS_DIR/resolved_ips.txt" -o "$PORTS_DIR/targets.txt"
else
    # Fallback: parallel dig
    cat "$PORTS_DIR/targets_raw.txt" | xargs -P 20 -I{} sh -c '
        host="{}"
        if echo "$host" | grep -Eq "^([0-9]{1,3}\.){3}[0-9]{1,3}$"; then
            echo "$host"
        else
            dig +short "$host" 2>/dev/null | grep -E "^[0-9]+\." | head -n 1
        fi
    ' > "$PORTS_DIR/targets.txt" 2>/dev/null
    sort -u "$PORTS_DIR/targets.txt" -o "$PORTS_DIR/targets.txt"
fi
```

#### Bash Perf 2 — Parallelize Phase 2 RustScan (`modules/02_intel.sh`, lines ~242-247)

**Problem:** Per-host sequential RustScan loop.

**Fix:** RustScan supports comma-separated addresses. Feed all at once:
```bash
if command -v rustscan &> /dev/null && [ "$TARGETS_COUNT" -gt 0 ]; then
    log_info "Running RustScan (fast port discovery on all targets)..."
    TARGETS_CSV=$(paste -sd, "$PORTS_DIR/targets.txt")
    rustscan -a "$TARGETS_CSV" -b "$RUSTSCAN_BATCH" -t "$RUSTSCAN_TIMEOUT" \
        --ulimit 5000 --range 1-65535 $RUSTSCAN_NO_NMAP \
        > "$PORTS_DIR/rustscan_raw.txt" 2>/dev/null || log_warn "RustScan failed"
    # ... parse output same as before
fi
```

#### Bash Perf 3 — Use Nmap `-iL` for Batch Scanning (`modules/02_intel.sh`, lines ~281-307)

**Problem:** Nmap scans hosts one at a time in a while loop.

**Fix:** Use Nmap's native input list:
```bash
if command -v nmap &> /dev/null && [ "$TARGETS_COUNT" -gt 0 ]; then
    log_info "Running Nmap (deep service detection on all targets)..."
    NMAP_TARGETS="$PORTS_DIR/nmap_targets.txt"
    head -n "$NMAP_MAX_HOSTS" "$PORTS_DIR/targets.txt" > "$NMAP_TARGETS"

    timeout $((NMAP_HOST_TIMEOUT * NMAP_MAX_HOSTS)) \
        nmap -sV -sC -T4 -Pn $NMAP_PORT_FLAG \
        --host-timeout "${NMAP_HOST_TIMEOUT}s" \
        --min-parallelism 10 \
        -iL "$NMAP_TARGETS" \
        -oX "$PORTS_DIR/nmap_all.xml" \
        -oN "$PORTS_DIR/nmap_all.txt" \
        2>/dev/null || log_warn "Nmap failed or timed out"
fi
```

This eliminates the per-host loop, per-host XML merge, and per-host disk space checks (Nmap manages output itself).

#### Bash Perf 4 — Parallelize Phase 3 Brute-Force Loops (`modules/03_content.sh`)

**Problem:** FFUF, Feroxbuster, and Dirsearch each iterate hosts sequentially.

**Fix:** Use `xargs -P` for all three. Example for FFUF:
```bash
if command -v ffuf &> /dev/null; then
    log_info "Running FFUF (parallel)..."
    export WORDLIST FFUF_THREADS FFUF_TIMEOUT BRUTE_DIR
    cat "$BRUTE_DIR/brute_targets.txt" | xargs -P 5 -I{} bash -c '
        host="{}"
        log_info "FFUF: $host"
        ffuf -u "https://$host/FUZZ" -w "$WORDLIST" \
            -mc 200,201,202,203,204,301,302,307,308,401,403 \
            -t "$FFUF_THREADS" -timeout "$FFUF_TIMEOUT" -s -json \
            -o "$BRUTE_DIR/ffuf_${host//[^a-zA-Z0-9]/_}.json" 2>/dev/null || true
    '
    cat "$BRUTE_DIR"/ffuf_*.json 2>/dev/null > "$BRUTE_DIR/ffuf_all.json" || touch "$BRUTE_DIR/ffuf_all.json"
fi
```

Apply the same `xargs -P` pattern to Feroxbuster and Dirsearch loops.

#### Bash Perf 5 — Consolidate 5 Nuclei Runs Into 1 (`modules/04_vuln.sh`, lines ~134-175)

**Problem:** Nuclei is invoked 5 separate times: critical/high, medium, low/info, CVE tags, misconfig tags. Each re-downloads templates and re-scans URLs.

**Fix:** Replace with a single invocation:
```bash
if command -v nuclei &> /dev/null && [ "$SCAN_COUNT" -gt 0 ]; then
    log_info "Running Nuclei (all templates, all severities)..."
    nuclei -update-templates 2>/dev/null || log_warn "Failed to update Nuclei templates"

    cat "$PHASE_DIR/scan_urls.txt" | \
        nuclei -silent -json \
        -severity critical,high,medium,low,info \
        -rate-limit "$NUCLEI_RATE_HIGH" \
        -o "$NUCLEI_DIR/nuclei_all.json" 2>/dev/null || log_warn "Nuclei scan failed"

    NUCLEI_COUNT=$(wc -l < "$NUCLEI_DIR/nuclei_all.json" 2>/dev/null | tr -d ' ')
    log_info "Nuclei findings: ${NUCLEI_COUNT:-0}"
fi
```

#### Bash Perf 6 — Parallelize Phase 3 JS Analysis (`modules/03_content.sh`, lines ~363-372)

**Problem:** LinkFinder and SecretFinder iterate 100 JS files sequentially.

**Fix:**
```bash
if command -v linkfinder &> /dev/null || [ -f "/opt/LinkFinder/linkfinder.py" ]; then
    log_info "Running LinkFinder (parallel)..."
    head -n 100 "$URLS_DIR/javascript_files.txt" | xargs -P 10 -I{} bash -c '
        js_url="{}"
        if [ -f "/opt/LinkFinder/linkfinder.py" ]; then
            python3 /opt/LinkFinder/linkfinder.py -i "$js_url" -o cli 2>/dev/null
        else
            linkfinder -i "$js_url" -o cli 2>/dev/null
        fi
    ' >> "$JS_DIR/linkfinder_endpoints.txt" 2>/dev/null
    sort -u "$JS_DIR/linkfinder_endpoints.txt" -o "$JS_DIR/linkfinder_endpoints.txt" 2>/dev/null || true
fi
```

Same for SecretFinder.

---

### PRIORITY 4: Extract Shared Bash Utilities

#### Create `lib/common.sh`

Create a new file `lib/common.sh` containing all shared functions:
```bash
#!/bin/bash
# Technieum shared utilities — sourced by all phase modules

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[+]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }

safe_cat() {
    local output_file="$1"; shift
    > "$output_file"
    for file in "$@"; do
        if [ -f "$file" ] && [ -s "$file" ]; then
            cat "$file" >> "$output_file" 2>/dev/null || true
        fi
    done
    return 0
}

safe_grep() { grep "$@" || true; }

tool_supports_flag() {
    local tool="$1" flag="$2"
    command -v "$tool" &>/dev/null || return 1
    "$tool" -h 2>&1 | grep -q -- "$flag"
}

run_tool() {
    local tool_name="$1" output_file="$2" timeout_duration="${3:-600}"
    shift 3; local cmd="$@"
    if ! command -v "$tool_name" &>/dev/null; then
        log_warn "$tool_name not installed, skipping..."
        return 2
    fi
    log_info "Running $tool_name (timeout: ${timeout_duration}s)..."
    local start_time=$(date +%s)
    if timeout "$timeout_duration" bash -c "$cmd" 2>"${output_file}.err"; then
        local duration=$(( $(date +%s) - start_time ))
        log_info "$tool_name completed (${duration}s)"
        return 0
    else
        local exit_code=$? duration=$(( $(date +%s) - start_time ))
        if [ $exit_code -eq 124 ]; then
            log_error "$tool_name timed out after ${timeout_duration}s"
        else
            log_error "$tool_name failed with exit code $exit_code (${duration}s)"
        fi
        return 1
    fi
}

check_disk_space() {
    local dir="$1" min_mb="${2:-1024}"
    local avail_kb
    avail_kb=$(df -k "$dir" 2>/dev/null | awk 'NR==2{print $4}')
    if [ -n "$avail_kb" ] && [ "$avail_kb" -lt $((min_mb * 1024)) ]; then
        log_error "Low disk space: $(( avail_kb / 1024 ))MB free (minimum: ${min_mb}MB)"
        return 1
    fi
    return 0
}

export -f log_info log_error log_warn safe_cat safe_grep
```

Then update all 4 modules to source it at the top:
```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
```

And **remove** the duplicated function definitions from each module.

---

### PRIORITY 5: Config Loading & Logging & Dotenv

#### 5A — Load config.yaml (`technieum.py`)

Add a config loader at the top of `Technieum.__init__`:
```python
import yaml

def _load_config(self, config_path: str = None) -> Dict[str, Any]:
    """Load config.yaml, merge with env vars (env takes precedence)"""
    if config_path is None:
        config_path = Path(__file__).parent / "config.yaml"
    config = {}
    if Path(config_path).exists():
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f) or {}
    return config
```

Call it in `__init__` and wire the values:
```python
self.config = self._load_config()
general = self.config.get('general', {})
self.threads = threads or general.get('threads', 5)
# etc.
```

#### 5B — Load .env (`technieum.py`)

Add at the very top of the file, before any other imports that use env vars:
```python
from dotenv import load_dotenv
load_dotenv()
```

#### 5C — Replace print() with logging (`technieum.py`)

Replace the manual `log_info/error/warn` methods with Python's logging module:
```python
import logging
from logging.handlers import RotatingFileHandler

def _setup_logging(self):
    """Configure logging with file + console handlers"""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    logger = logging.getLogger('technieum')
    logger.setLevel(logging.DEBUG)

    # Console handler
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(console)

    # File handler
    file_handler = RotatingFileHandler(
        log_dir / 'technieum.log', maxBytes=10*1024*1024, backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    logger.addHandler(file_handler)

    return logger
```

Replace `self.log_info(msg)` with `self.logger.info(msg)`, `self.log_error(msg)` with `self.logger.error(msg)`, etc. Keep the color formatting for console output by using a custom formatter that adds ANSI codes based on log level.

#### 5D — Add tqdm Progress Bars (`technieum.py`)

Wrap the phase execution in `scan_target` with tqdm:
```python
from tqdm import tqdm

# In scan_target:
phase_names = {1: "Discovery", 2: "Intelligence", 3: "Content", 4: "Vulnerability"}
active_phases = [p for p in phases if p in phase_names]

with tqdm(active_phases, desc=f"Scanning {target}", unit="phase") as pbar:
    for phase_num in pbar:
        pbar.set_postfix_str(phase_names[phase_num])
        # ... run phase ...
```

---

### PRIORITY 6: TEST_MODE Implementation

#### 6A — Create `tests/mock_data.py`

Create a new file `tests/mock_data.py`:
```python
"""Mock data for TEST_MODE — bypasses all live scanning"""

MOCK_SUBDOMAINS = [
    {"host": "test.example.com", "source_tool": "subfinder"},
    {"host": "api.example.com", "source_tool": "amass"},
    {"host": "dev.example.com", "source_tool": "crtsh"},
    {"host": "staging.example.com", "source_tool": "assetfinder"},
    {"host": "mail.example.com", "source_tool": "sublist3r"},
]

MOCK_ALIVE_HOSTS = [
    {"host": "test.example.com", "is_alive": True, "status_code": 200, "source_tool": "httpx"},
    {"host": "api.example.com", "is_alive": True, "status_code": 200, "source_tool": "httpx"},
    {"host": "dev.example.com", "is_alive": True, "status_code": 301, "source_tool": "httpx"},
]

MOCK_PORTS = [
    {"host": "test.example.com", "port": 80, "protocol": "tcp", "service": "http", "version": "nginx 1.24"},
    {"host": "test.example.com", "port": 443, "protocol": "tcp", "service": "https", "version": "nginx 1.24"},
    {"host": "api.example.com", "port": 443, "protocol": "tcp", "service": "https", "version": ""},
    {"host": "api.example.com", "port": 8080, "protocol": "tcp", "service": "http-proxy", "version": ""},
]

MOCK_URLS = [
    {"url": "https://test.example.com/api/v1/users", "source_tool": "gau"},
    {"url": "https://test.example.com/api/v1/login", "source_tool": "waybackurls"},
    {"url": "https://api.example.com/graphql", "source_tool": "katana"},
    {"url": "https://dev.example.com/admin/config.php", "source_tool": "ffuf"},
    {"url": "https://test.example.com/js/app.bundle.js", "source_tool": "hakrawler"},
]

MOCK_VULNS = [
    {"tool": "nuclei", "host": "test.example.com", "name": "Exposed Admin Panel", "severity": "high", "info": "Admin panel accessible without auth", "cve": ""},
    {"tool": "nuclei", "host": "dev.example.com", "name": "Directory Listing Enabled", "severity": "medium", "info": "Directory listing on /backup/", "cve": ""},
    {"tool": "dalfox", "host": "test.example.com", "name": "Reflected XSS", "severity": "high", "info": "XSS in search parameter", "cve": ""},
    {"tool": "sqlmap", "host": "api.example.com", "name": "SQL Injection", "severity": "critical", "info": "Boolean-based blind SQLi in id param", "cve": ""},
]

MOCK_LEAKS = [
    {"leak_type": "JS_Secret", "url": "https://test.example.com/js/app.bundle.js", "info": "AWS_ACCESS_KEY_ID found in JS", "severity": "high"},
    {"leak_type": "Git", "url": ".env", "info": "DATABASE_URL with credentials", "severity": "high"},
]

# Mock file contents that parsers expect
MOCK_FILES = {
    "phase1_discovery": {
        "all_subdomains.txt": "test.example.com\napi.example.com\ndev.example.com\nstaging.example.com\nmail.example.com\n",
        "resolved_subdomains.txt": "test.example.com\napi.example.com\ndev.example.com\n",
        "alive_hosts.txt": "test.example.com\napi.example.com\ndev.example.com\n",
        "passive_subdomains.txt": "test.example.com\napi.example.com\ndev.example.com\nstaging.example.com\nmail.example.com\n",
        "httpx_alive.json": '{"host":"test.example.com","url":"https://test.example.com","status_code":200}\n{"host":"api.example.com","url":"https://api.example.com","status_code":200}\n{"host":"dev.example.com","url":"https://dev.example.com","status_code":301}\n',
        "dnsx_resolved.json": '{"host":"test.example.com","a":["93.184.216.34"]}\n{"host":"api.example.com","a":["93.184.216.35"]}\n{"host":"dev.example.com","a":["93.184.216.36"]}\n',
    },
    "phase2_intel": {
        "ports/nmap_all.xml": '<?xml version="1.0"?><nmaprun><host><address addr="93.184.216.34" addrtype="ipv4"/><hostnames><hostname name="test.example.com"/></hostnames><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" version="nginx 1.24"/></port><port protocol="tcp" portid="443"><state state="open"/><service name="https" version="nginx 1.24"/></port></ports></host></nmaprun>',
    },
    "phase3_content": {
        "urls/gau.txt": "https://test.example.com/api/v1/users\nhttps://test.example.com/api/v1/login\n",
        "urls/waybackurls.txt": "https://test.example.com/api/v1/login\nhttps://test.example.com/old/page\n",
        "urls/katana.txt": "https://api.example.com/graphql\n",
        "urls/all_urls.txt": "https://test.example.com/api/v1/users\nhttps://test.example.com/api/v1/login\nhttps://api.example.com/graphql\nhttps://dev.example.com/admin/config.php\nhttps://test.example.com/js/app.bundle.js\n",
        "javascript/secretfinder_secrets.txt": "https://test.example.com/js/app.bundle.js - AWS_ACCESS_KEY_ID found\n",
        "javascript/linkfinder_endpoints.txt": "/api/v1/users\n/api/v1/admin\n/api/internal/health\n",
    },
    "phase4_vulnscan": {
        "nuclei/nuclei_all.json": '{"host":"test.example.com","info":{"name":"Exposed Admin Panel","severity":"high","description":"Admin panel accessible without auth"}}\n{"host":"dev.example.com","info":{"name":"Directory Listing Enabled","severity":"medium","description":"Directory listing on /backup/"}}\n',
        "xss/dalfox_results.txt": "[V] [VULN] Reflected XSS at https://test.example.com/search?q=test\n",
        "sqli/sqlmap_results.txt": "URL: https://api.example.com/api?id=1\nParameter: id (GET)\nType: boolean-based blind\nthe target URL is vulnerable\n",
    },
}
```

#### 6B — Create `tests/__init__.py`

Empty file to make tests a package.

#### 6C — Implement TEST_MODE in `technieum.py`

Add `--test` flag to argparse:
```python
parser.add_argument('--test', action='store_true', help='Run in test mode with mock data (no live scanning)')
```

Add test mode method to `Technieum`:
```python
def scan_target_test_mode(self, target: str, phases: List[int]) -> bool:
    """Run scan with mock data for testing"""
    from tests.mock_data import MOCK_FILES

    self.logger.info(f"[TEST MODE] Simulating scan for {target}")
    target_dir = self.output_dir / target.replace('.', '_')

    # Write mock output files
    for phase_dir_name, files in MOCK_FILES.items():
        phase_dir = target_dir / phase_dir_name
        for file_path, content in files.items():
            full_path = phase_dir / file_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content)

    # Initialize target in database
    self.db.init_target(target)

    # Run parsers against mock files (same as production)
    if 1 in phases:
        self.parse_phase1_output(target, target_dir)
        self.db.update_phase(target, 1, True)
    if 2 in phases:
        self.parse_phase2_output(target, target_dir)
        self.db.update_phase(target, 2, True)
    if 3 in phases:
        self.parse_phase3_output(target, target_dir)
        self.db.update_phase(target, 3, True)
    if 4 in phases:
        self.parse_phase4_output(target, target_dir)
        self.db.update_phase(target, 4, True)

    self.logger.info(f"[TEST MODE] Scan complete for {target}")
    return True
```

Wire it into `scan_target`:
```python
def scan_target(self, target: str, phases: List[int]) -> bool:
    if self.test_mode:
        return self.scan_target_test_mode(target, phases)
    # ... existing production code ...
```

#### 6D — Create `tests/test_parsers.py`

```python
"""Unit tests for all parsers"""
import pytest
import tempfile
import os
from parsers.parser import (
    SubdomainParser, HttpParser, DnsParser, PortParser,
    UrlParser, DirectoryParser, VulnerabilityParser,
    LeakParser, TakeoverParser
)
from tests.mock_data import MOCK_FILES


class TestSubdomainParser:
    def setup_method(self):
        self.parser = SubdomainParser()

    def test_parse_generic_list(self, tmp_path):
        f = tmp_path / "subs.txt"
        f.write_text("test.example.com\napi.example.com\ninvalid\n")
        result = self.parser.parse_generic_list(str(f), "test")
        assert len(result) == 2
        assert result[0]['host'] == 'test.example.com'
        assert result[0]['source_tool'] == 'test'


class TestHttpParser:
    def setup_method(self):
        self.parser = HttpParser()

    def test_parse_httpx(self, tmp_path):
        f = tmp_path / "httpx.json"
        f.write_text(MOCK_FILES["phase1_discovery"]["httpx_alive.json"])
        result = self.parser.parse_httpx(str(f))
        assert len(result) == 3
        assert all(r['is_alive'] for r in result)


class TestPortParser:
    def setup_method(self):
        self.parser = PortParser()

    def test_parse_nmap_xml(self, tmp_path):
        f = tmp_path / "nmap.xml"
        f.write_text(MOCK_FILES["phase2_intel"]["ports/nmap_all.xml"])
        result = self.parser.parse_nmap_xml(str(f))
        assert len(result) == 2
        assert result[0]['port'] == 80


class TestDirectoryParser:
    def setup_method(self):
        self.parser = DirectoryParser()

    def test_parse_ffuf(self, tmp_path):
        """Verify the FFUF parser bug is fixed"""
        f = tmp_path / "ffuf.json"
        f.write_text('{"results": [{"url": "https://example.com/admin", "status": 200}]}')
        result = self.parser.parse_ffuf(str(f))
        assert len(result) == 1
        assert result[0]['url'] == 'https://example.com/admin'


class TestVulnerabilityParser:
    def setup_method(self):
        self.parser = VulnerabilityParser()

    def test_parse_nuclei(self, tmp_path):
        f = tmp_path / "nuclei.json"
        f.write_text(MOCK_FILES["phase4_vulnscan"]["nuclei/nuclei_all.json"])
        result = self.parser.parse_nuclei(str(f))
        assert len(result) == 2
        assert result[0]['severity'] == 'high'
```

#### 6E — Create `tests/test_database.py`

```python
"""Unit tests for database operations"""
import pytest
import tempfile
import os
from db.database import DatabaseManager


@pytest.fixture
def db():
    """Create a temporary database for testing"""
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    manager = DatabaseManager(path)
    yield manager
    manager.close()
    os.unlink(path)


class TestDatabaseManager:
    def test_init_target(self, db):
        db.init_target("example.com")
        progress = db.get_progress("example.com")
        assert progress is not None
        assert progress['phase1_done'] == 0

    def test_insert_subdomains_bulk(self, db):
        db.init_target("example.com")
        subs = [
            {"host": "a.example.com", "source_tool": "test"},
            {"host": "b.example.com", "source_tool": "test"},
        ]
        db.insert_subdomains_bulk("example.com", subs)
        all_subs = db.get_all_subdomains("example.com")
        assert len(all_subs) == 2

    def test_bulk_insert_updates_alive(self, db):
        """Verify that Bug 3 is fixed — bulk insert should update is_alive"""
        db.init_target("example.com")
        # First insert: not alive
        db.insert_subdomains_bulk("example.com", [
            {"host": "a.example.com", "source_tool": "subfinder", "is_alive": False}
        ])
        # Second insert: mark alive
        db.insert_subdomains_bulk("example.com", [
            {"host": "a.example.com", "source_tool": "httpx", "is_alive": True}
        ])
        alive = db.get_alive_hosts("example.com")
        assert "a.example.com" in alive

    def test_get_stats(self, db):
        db.init_target("example.com")
        stats = db.get_stats("example.com")
        assert stats['subdomains'] == 0
        assert stats['vulnerabilities'] == 0

    def test_different_db_paths(self):
        """Verify that Bug 2 is fixed — different paths create different DBs"""
        import tempfile, os
        fd1, path1 = tempfile.mkstemp(suffix='.db')
        fd2, path2 = tempfile.mkstemp(suffix='.db')
        os.close(fd1)
        os.close(fd2)
        try:
            db1 = DatabaseManager(path1)
            db2 = DatabaseManager(path2)
            assert db1.db_path != db2.db_path
            db1.close()
            db2.close()
        finally:
            os.unlink(path1)
            os.unlink(path2)
```

#### 6F — Create `tests/test_integration.py`

```python
"""Integration test using TEST_MODE"""
import pytest
import tempfile
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from technieum import Technieum


class TestIntegration:
    def test_full_test_mode_scan(self, tmp_path):
        """End-to-end test: TEST_MODE scans, parses, and queries in < 5 seconds"""
        db_path = str(tmp_path / "test.db")
        output_dir = str(tmp_path / "output")

        technieum = Technieum(
            targets=["example.com"],
            output_dir=output_dir,
            db_path=db_path,
            threads=1,
        )
        technieum.test_mode = True

        success = technieum.scan_target("example.com", [1, 2, 3, 4])
        assert success

        stats = technieum.db.get_stats("example.com")
        assert stats['subdomains'] > 0
        assert stats['alive_hosts'] > 0
        assert stats['urls'] > 0
        assert stats['vulnerabilities'] > 0
```

---

### PRIORITY 7: Cleanup

#### 7A — Clean Up `requirements.txt`

After wiring all the libraries, the requirements.txt should reflect actual usage:
```
# Core (actually used)
pyyaml>=6.0.0
aiohttp>=3.9.0
colorama>=0.4.6
tqdm>=4.66.0
python-dotenv>=1.0.0
tabulate>=0.9.0
lxml>=4.9.3

# Testing
pytest>=7.0.0

# Remove these (unused):
# requests>=2.31.0  — not imported anywhere
# beautifulsoup4>=4.12.0  — not imported anywhere
# dnspython>=2.4.0  — not imported anywhere
```

If `requests`, `beautifulsoup4`, or `dnspython` are actually used somewhere I missed, keep them. Otherwise remove.

#### 7B — Add Database Cleanup

Add `close()` call at the end of `technieum.py:main()`:
```python
try:
    technieum.run(phases=phases)
finally:
    technieum.db.close()
```

---

## Global Constraints

1. **Do NOT change external tool CLI invocations** in bash — those tools are third-party.
2. **Do NOT change the database schema** — maintain backward compatibility with existing `technieum.db` files.
3. **Do NOT remove any existing CLI flags** — all of `-t`, `-f`, `-o`, `-d`, `-p`, `-T`, `--resume` must continue working.
4. **Preserve the 4-phase sequential architecture** — phases depend on each other.
5. **Every file you modify must be shown in full** — no partial snippets.
6. **Create the `lib/` directory, `tests/` directory, and all new files** as specified.
7. **Run-test the changes mentally** — ensure imports resolve, method signatures match, and the data flow is consistent from bash output -> parser -> database -> query tool.

## Deliverable

Provide the **complete updated contents** of every file you modify or create:

- `technieum.py` (modified)
- `db/database.py` (modified)
- `parsers/parser.py` (modified)
- `query.py` (modified)
- `modules/01_discovery.sh` (modified)
- `modules/02_intel.sh` (modified)
- `modules/03_content.sh` (modified)
- `modules/04_vuln.sh` (modified)
- `requirements.txt` (modified)
- `lib/common.sh` (new)
- `tests/__init__.py` (new)
- `tests/mock_data.py` (new)
- `tests/test_parsers.py` (new)
- `tests/test_database.py` (new)
- `tests/test_integration.py` (new)

For each file, output:
```
### FILE: <path>
```
Followed by the complete file content in a code block.
