# Code Audit & Refactoring Specification

**Project:** ReconX - Attack Surface Management Framework
**Auditor:** Automated Code Auditor (Claude Opus 4.6)
**Date:** 2026-02-10
**Codebase:** ~3,700 LOC (Python + Bash) across 10 core files

---

## 1. Executive Summary

| Metric | Value |
| :--- | :--- |
| **Current Quality Score** | **4 / 10** |
| **Primary Flaw** | Sequential blocking I/O at every layer: `subprocess.run()` buffers entire phase outputs (30-120 min) before returning, bash modules execute tools in serial `while read` loops, parsers slurp entire files into memory, and the DB commits after every single INSERT |
| **Estimated Speed Improvement** | **5-8x faster** with async subprocess streaming, parallel host loops in bash, batched DB transactions, and streaming parsers |
| **Test Readiness** | **0%** - No test suite, no mock data path, no TEST_MODE flag, 6 of 9 declared dependencies (`aiohttp`, `requests`, `tqdm`, `beautifulsoup4`, `dnspython`, `colorama`) are installed but never imported |

---

## 2. Bottleneck Analysis

### 2.1 Python Layer

| Location | Issue Type | Severity | Description |
| :--- | :--- | :--- | :--- |
| `reconx.py:133` `subprocess.run(capture_output=True)` | **Blocking I/O** | **Critical** | Each phase script runs 30-120 min. `capture_output=True` buffers ALL stdout/stderr in memory until the script exits. The user sees zero output until the entire phase completes. A 4-phase scan can appear frozen for hours. |
| `reconx.py:456` `run(phases=[1,2,3,4])` | **Mutable Default Arg** | Medium | Default list arg `[1,2,3,4]` is shared across calls. Classic Python footgun. |
| `reconx.py:68-76` Parser instantiation | **Wasted Allocation** | Low | All 9 parser objects are created in `__init__` even if only 1 phase runs. Trivial memory cost but signals missing lazy-init pattern. |
| `reconx.py` (entire file) | **Dead Config** | Medium | `config.yaml` exists with 221 lines of settings but is **never loaded**. All config comes from env vars or hardcoded defaults. The YAML file is decorative. |
| `parsers/parser.py:18-25` `read_lines()` | **Memory Bomb** | **High** | Reads entire file into a list. Phase 3 can produce `all_urls.txt` with 500K+ lines. For 10 targets in parallel, this is 5M+ strings in memory simultaneously. |
| `parsers/parser.py:28-51` `read_json()` | **Double Memory** | **High** | Calls `f.read()` to load entire content as a string, then `json.loads()` to parse into a second in-memory object. Peak memory = 2x file size. Nuclei JSON can be 100MB+. |
| `parsers/parser.py:298-310` `parse_ffuf()` | **Logic Bug** | **High** | `read_json()` returns a `List[Dict]`. The code then checks `if 'results' in data` which tests list membership, not dict key access. This always evaluates `False` for ffuf's JSON structure (`{"results": [...]}`). **FFUF results are silently dropped and never enter the database.** |
| `parsers/parser.py:487-500` `get_parser()` factory | **Object Churn** | Low | Creates 9 new parser instances on every call. Should cache or use class methods. |
| `parsers/parser.py:253-292` URL parsers | **Code Duplication** | Medium | `parse_gau`, `parse_waybackurls`, `parse_hakrawler`, `parse_katana` are identical except for the `source_tool` string. 4 copies of the same 3-line function. |
| `parsers/parser.py:59,66` Regex | **Repeated Compilation** | Medium | `re.match(pattern, ...)` recompiles the regex on every call. `extract_domain` and `is_valid_subdomain` are called thousands of times per parse. |
| `db/database.py:22-28` Singleton `__new__` | **Stale Path Bug** | **High** | The Singleton caches the first `db_path` forever. If `DatabaseManager("scan1.db")` is created, then later `DatabaseManager("scan2.db")` is called, the second path is **silently ignored** and all data goes to `scan1.db`. The `--database` CLI flag is broken for any session after the first. |
| `db/database.py:209-215` `execute()` | **Commit-Per-Statement** | **High** | Every single `INSERT`, `UPDATE`, and even `SELECT` triggers an immediate `conn.commit()`. During Phase 1 parsing, 5,000 subdomains = 5,000 commits = 5,000 fsync() calls. This is the #1 database bottleneck. |
| `db/database.py:372-382` `insert_subdomains_bulk()` | **Silent Data Loss** | **High** | Uses `INSERT OR IGNORE` which silently discards rows that conflict. But the single-row `insert_subdomain()` at line 357 uses `ON CONFLICT ... DO UPDATE` which merges data. Bulk inserts from Phase 1 (httpx alive hosts) that should update `is_alive=True` on existing rows are **silently dropped** instead. |
| `db/database.py:504-540` `get_stats()` | **N+1 Query** | Medium | Makes 8 separate `SELECT COUNT(*)` queries when a single query with conditional aggregation would suffice. |
| `query.py:200` `export_csv()` | **SQL Injection** | **Critical** | `f"SELECT * FROM {table} WHERE target = ?"` interpolates user-supplied `table` directly into SQL. The `--export` arg is constrained by argparse choices, but the method itself is injectable if called from other code. |
| `requirements.txt` | **Phantom Dependencies** | Medium | 6 packages declared but never used: `aiohttp`, `requests`, `beautifulsoup4`, `dnspython`, `colorama`, `python-dotenv`. Increases install time, widens attack surface, confuses developers. |

### 2.2 Bash Layer

| Location | Issue Type | Severity | Description |
| :--- | :--- | :--- | :--- |
| `01_discovery.sh:372` `local exit_code=$?` | **Syntax Error** | Medium | `local` keyword used outside a function body (inside a bare `for` loop at script scope). Bash silently ignores this on some versions but it's undefined behavior and will fail on strict shells. |
| `02_intel.sh:199-227` DNS resolution loop | **Serial Blocking I/O** | **High** | Resolves each hostname with `dig +short` one at a time in a `while read` loop. For 500 hosts, this is 500 sequential DNS lookups (~3-5 min of pure waiting). Should use `dnsx` or GNU parallel. |
| `02_intel.sh:242-247` RustScan loop | **Serial Scanning** | **High** | Port-scans each host individually in a `while read` loop. RustScan natively supports file input (`-a` with multiple hosts or `-i` for input file). This serializes what should be a single parallel scan. |
| `02_intel.sh:281-307` Nmap loop | **Serial Scanning** | **High** | Scans hosts one at a time. Nmap supports `-iL` for input file with built-in parallelism. The current approach adds NMAP_HOST_TIMEOUT * N_HOSTS seconds of sequential delay. |
| `02_intel.sh:337-342` Shodan loop | **Serial API Calls** | Medium | Queries Shodan for each host sequentially. Could use `xargs -P` or background jobs. |
| `03_content.sh:286-294` FFUF loop | **Serial Brute-Force** | **High** | Brute-forces each of 20 hosts sequentially. At ~2 min/host, this is 40 min that could be 4 min with 10x parallelism. Same issue for Feroxbuster (line 306) and Dirsearch (line 325). |
| `03_content.sh:363-372` LinkFinder loop | **Serial JS Analysis** | Medium | Processes 100 JS files one at a time. Each `linkfinder` call makes an HTTP request + regex extraction. ~1-3s per file = 5 min serial. |
| `04_vuln.sh:143-167` Nuclei 5-pass scan | **Redundant Scans** | **High** | Runs Nuclei **5 separate times** over the same URL list (critical/high, medium, low/info, CVE, misconfig). Each pass re-downloads and re-parses all templates. A single `nuclei` invocation with all severities and `--json` output is 3-5x faster. |
| All modules | **Duplicated Utilities** | Medium | `safe_cat()`, `safe_grep()`, `log_info()`, `log_error()`, `log_warn()` are copy-pasted into all 4 modules (~25 lines each x 4 = 100 lines of duplication). Should be sourced from a shared `lib/common.sh`. |
| All modules | **No config.yaml** | Medium | Every tunable is via env vars. The config.yaml has matching settings that are never read. The bash modules should source values from config.yaml (via `yq` or a Python config loader). |

### 2.3 Architectural Issues

| Issue | Severity | Description |
| :--- | :--- | :--- |
| **No TEST_MODE** | **Critical** | There is zero ability to run the tool with mock/hardcoded data. Every test requires live network access, 50+ installed tools, and hours of wall time. This makes development, CI/CD, and debugging effectively impossible. |
| **No Logging Framework** | High | All logging is raw `print()` with ANSI codes. No log levels, no file logging, no structured logging. The `logging` module is never imported despite `config.yaml` having logging settings. |
| **No config.yaml Loader** | High | `config.yaml` (221 lines) is never read by any code. `pyyaml` is installed but never imported. All config is env-var only. |
| **No Connection Lifecycle** | Medium | `DatabaseManager.close()` is never called anywhere. Thread-local connections are never cleaned up. The SQLite WAL checkpoint never runs. |
| **subprocess.run vs Popen** | Critical | `subprocess.run()` with `capture_output=True` is fundamentally wrong for long-running scripts. It blocks the calling thread and buffers all output. `subprocess.Popen` with streaming `stdout` would provide real-time output and lower memory usage. |
| **No Deduplication in Parsing** | Medium | Parsers return lists with duplicates. The DB handles dedup via `UNIQUE` constraints and `INSERT OR IGNORE`, but this means the DB rejects thousands of rows per bulk insert. Pre-deduplicating in Python (via `set`) would reduce DB write load by 30-60%. |

---

## 3. Refactoring Specification

### 3.1 Architecture

| Aspect | Current | Target |
| :--- | :--- | :--- |
| **Pattern** | Monolithic sequential orchestrator | Event-driven orchestrator with streaming subprocess I/O |
| **Subprocess Strategy** | `subprocess.run(capture_output=True)` (blocking) | `subprocess.Popen` with `asyncio.create_subprocess_exec` or threaded `readline()` for real-time streaming |
| **Concurrency (Python)** | `ThreadPoolExecutor` for multi-target only | `ThreadPoolExecutor` for multi-target + `asyncio` for I/O-bound parsing and DB writes |
| **Concurrency (Bash)** | `wait` for background jobs in Phase 1 only; serial `while read` loops elsewhere | `xargs -P` / GNU `parallel` / background jobs with `wait` for all serial loops |
| **Database** | Commit-per-statement | Batched transactions with `BEGIN`/`COMMIT` wrapping bulk operations |
| **Config** | 100% env vars (config.yaml unused) | Load `config.yaml` with `pyyaml`, override with env vars |
| **Logging** | Raw `print()` with ANSI codes | Python `logging` module with file + console handlers; `tqdm` for progress bars |
| **Testing** | None | `TEST_MODE` flag with hardcoded datasets; `pytest` test suite |

### 3.2 Required Libraries (already in requirements.txt)

| Library | Status | Purpose |
| :--- | :--- | :--- |
| `pyyaml` | Installed, **unused** | Load config.yaml |
| `aiohttp` | Installed, **unused** | Async HTTP for future API-based tool integrations |
| `tqdm` | Installed, **unused** | Progress bars for phase/tool tracking |
| `colorama` | Installed, **unused** | Cross-platform ANSI color support (replace manual codes) |
| `python-dotenv` | Installed, **unused** | Load `.env` file for API keys |

**New dependencies needed:** None. Everything required is already declared but unused.

### 3.3 Feature Requirements

#### 3.3.1 TEST_MODE Flag

**Requirement:** Accept a flag (`--test` CLI arg or `TEST_MODE=true` env var) that bypasses all live scanning and uses hardcoded mock data.

| Aspect | Specification |
| :--- | :--- |
| **Activation** | CLI: `python3 reconx.py -t example.com --test` or Env: `TEST_MODE=true` |
| **Behavior IF ON** | Skip all `subprocess` calls to bash modules. Instead, write pre-defined mock output files to the phase directories and run parsers against them. Use hardcoded data: `MOCK_SUBDOMAINS = ["test.example.com", "api.example.com", "dev.example.com"]`, `MOCK_URLS = ["https://test.example.com/api/v1", "https://api.example.com/login"]`, `MOCK_PORTS = [{"host": "test.example.com", "port": 443, "service": "https"}, {"host": "test.example.com", "port": 80, "service": "http"}]`, `MOCK_VULNS = [{"tool": "nuclei", "host": "test.example.com", "name": "Test XSS", "severity": "high"}]` |
| **Behavior IF OFF** | Run full production workload (current behavior) |
| **Mock Data Location** | New file: `tests/mock_data.py` containing all hardcoded datasets |
| **Output** | Must produce valid database entries identical in schema to real scan data |
| **Wall Time** | TEST_MODE must complete in < 5 seconds |

#### 3.3.2 Streaming Subprocess Output

**Requirement:** Replace `subprocess.run(capture_output=True)` with `subprocess.Popen` and line-by-line streaming.

```
# CURRENT (blocks for 30-120 min, buffers all output):
result = subprocess.run([script, target, dir], capture_output=True, text=True, timeout=timeout)
if result.stdout:
    print(result.stdout)

# TARGET (streams output in real-time):
process = subprocess.Popen([script, target, dir], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
for line in process.stdout:
    print(line, end='')
    # optionally: parse structured progress markers from bash scripts
process.wait()
```

#### 3.3.3 Batched Database Transactions

**Requirement:** Wrap bulk operations in explicit transactions.

```
# CURRENT (5000 subdomains = 5000 commits):
def execute(self, query, params):
    cursor.execute(query, params)
    conn.commit()  # fsync on every row

# TARGET (5000 subdomains = 1 commit):
def insert_subdomains_bulk(self, target, subdomains):
    conn = self._get_connection()
    conn.execute("BEGIN")
    try:
        cursor.executemany(query, data)
        conn.commit()
    except:
        conn.rollback()
        raise
```

#### 3.3.4 Fix Critical Bugs

| Bug | File:Line | Fix |
| :--- | :--- | :--- |
| **FFUF parser never works** | `parsers/parser.py:298-310` | `read_json()` returns a list. If the raw JSON is `{"results": [...]}`, it returns `[{"results": [...]}]`. Change to: `data = self.read_json(file_path); if data and isinstance(data[0], dict) and 'results' in data[0]: for entry in data[0]['results']: ...` |
| **Singleton ignores db_path** | `db/database.py:22-28` | Remove Singleton pattern entirely. Use a simple class that accepts `db_path` and manages its own connection. The orchestrator already creates a single instance. |
| **Bulk insert drops updates** | `db/database.py:379-382` | Change `INSERT OR IGNORE` to `INSERT ... ON CONFLICT DO UPDATE` matching the single-row method's behavior |
| **SQL injection in export** | `query.py:200` | Whitelist table names: `if table not in ALLOWED_TABLES: raise ValueError(...)` |
| **Mutable default arg** | `reconx.py:456` | Change to `phases: List[int] = None` with `if phases is None: phases = [1,2,3,4]` |

#### 3.3.5 Robustness

| Requirement | Specification |
| :--- | :--- |
| **Progress Tracking** | Wrap each phase in a `tqdm` progress bar showing: current tool name, elapsed time, tools completed/total |
| **Structured Logging** | Initialize Python `logging` with `RotatingFileHandler` at `logs/reconx.log` + `StreamHandler` for console. Replace all `print()` calls with `logger.info()` / `logger.error()` / `logger.warning()`. Load log level from `config.yaml`. |
| **Config Loading** | Add a `load_config()` function that reads `config.yaml` with `pyyaml`, merges with env vars (env takes precedence), and returns a typed config dict. Pass this config to `ReconX.__init__`. |
| **Dotenv Loading** | Call `load_dotenv()` from `python-dotenv` at startup to load `.env` file. |
| **Connection Cleanup** | Add `__del__` or context manager (`__enter__`/`__exit__`) to `DatabaseManager` to close connections. Call `db.close()` in `reconx.py` at shutdown. |
| **Pre-Deduplication** | Add `deduplicate()` to parsers that returns a `set`-based unique list before DB insertion. |

---

## 4. Step-by-Step Implementation Plan

### Phase A: Foundation (Non-Breaking)

1. **Create `tests/` directory and `tests/mock_data.py`** with hardcoded mock datasets for all 4 phases (subdomains, ports, URLs, vulns, leaks).

2. **Create `lib/common.sh`** with shared bash utilities (`safe_cat`, `safe_grep`, `log_info`, `log_error`, `log_warn`, `run_tool`). Update all 4 modules to `source "$SCRIPT_DIR/../lib/common.sh"`.

3. **Add `--test` flag to `argparse`** in `reconx.py:main()`. Pass it through to `ReconX.__init__` as `self.test_mode`.

4. **Load config.yaml** - Add `_load_config()` method to `ReconX` that reads `config.yaml` with `yaml.safe_load()`, merges with env vars. Wire phase timeouts, thread counts, and tool enables to config values.

5. **Load `.env`** - Add `from dotenv import load_dotenv; load_dotenv()` at the top of `reconx.py`.

6. **Replace logging** - Import `logging`, create a module-level logger, replace all `self.log_info/error/warn` with `logger.info/error/warning`. Add `RotatingFileHandler` writing to `logs/reconx.log`.

### Phase B: Fix Critical Bugs

7. **Fix FFUF parser** (`parsers/parser.py:298-310`): Handle both list-wrapped and raw dict formats from `read_json()`.

8. **Remove DatabaseManager Singleton** (`db/database.py:19-28`): Delete `_instance`, `_lock`, and `__new__`. Make it a plain class that initializes on `__init__`.

9. **Fix bulk insert semantics** (`db/database.py:379-382`): Change `INSERT OR IGNORE` to `INSERT ... ON CONFLICT(target, host) DO UPDATE SET ...` matching the single-row method.

10. **Fix SQL injection in export** (`query.py:200`): Add `ALLOWED_TABLES = {'subdomains', 'vulnerabilities', 'leaks', 'ports', 'urls'}` and validate before query.

11. **Fix mutable default** (`reconx.py:456`): Change `phases` default to `None`.

12. **Fix bash `local` outside function** (`01_discovery.sh:372`): Remove the `local` keyword.

### Phase C: Performance - Python Layer

13. **Replace `subprocess.run` with `Popen` streaming** in `run_module()`. Use `threading.Thread` to read `stdout` and `stderr` concurrently, printing lines in real-time.

14. **Batch DB transactions** - Modify `executemany()` to wrap in `BEGIN`/`COMMIT`. Remove `conn.commit()` from `execute()` and make commit explicit only in bulk methods.

15. **Consolidate `get_stats()` into a single query** using conditional `SUM(CASE WHEN ...)`.

16. **Pre-compile regexes** in parsers. Add class-level `_DOMAIN_RE = re.compile(...)` and `_SUBDOMAIN_RE = re.compile(...)`.

17. **Add streaming file readers** - Replace `read_lines()` with a generator `iter_lines()` that yields lines without loading the entire file. Replace `read_json()` with a streaming JSONL reader for large files.

18. **Pre-deduplicate** parser output using `set()` keyed on `(host,)` or `(url,)` before returning.

### Phase D: Performance - Bash Layer

19. **Parallelize Phase 2 DNS resolution** (`02_intel.sh:199-227`): Replace the `while read` loop with `xargs -P 20 -I{} dig +short {} | ...` or feed targets to `dnsx` (which is already installed).

20. **Parallelize Phase 2 RustScan** (`02_intel.sh:242-247`): Replace per-host loop with a single `rustscan -iL targets.txt` invocation.

21. **Parallelize Phase 2 Nmap** (`02_intel.sh:281-307`): Use `nmap -iL nmap_targets.txt` with `--min-parallelism 10` instead of per-host sequential invocations.

22. **Parallelize Phase 3 brute-force tools** (`03_content.sh:286-338`): Wrap FFUF, Feroxbuster, and Dirsearch `while read` loops in `xargs -P $THREADS` or launch as background jobs with a `wait` gate.

23. **Consolidate Nuclei runs** (`04_vuln.sh:134-175`): Replace 5 separate Nuclei invocations with a single run: `nuclei -severity critical,high,medium,low,info -tags cve,misconfiguration,config -json -rate-limit $RATE`.

24. **Parallelize Phase 3 JS analysis** (`03_content.sh:363-372`): Use `xargs -P 10` for LinkFinder and SecretFinder loops.

### Phase E: TEST_MODE Implementation

25. **Implement `scan_target_test_mode()`** in `reconx.py` that:
    - Creates phase directories
    - Writes mock output files from `tests/mock_data.py`
    - Calls parsers against mock files
    - Inserts parsed data into DB
    - Completes in < 5 seconds

26. **Add pytest test suite** in `tests/`:
    - `test_parsers.py` - Unit tests for all 9 parsers using mock data
    - `test_database.py` - Unit tests for DB operations (insert, bulk, stats, dedup)
    - `test_orchestrator.py` - Integration test using TEST_MODE end-to-end
    - `test_query.py` - Unit tests for query tool

27. **Add `Makefile` targets**: `make test` (runs pytest), `make test-quick` (TEST_MODE only), `make lint` (flake8/ruff).

### Phase F: Cleanup

28. **Remove unused dependencies** from `requirements.txt` if they remain unused after refactoring, or wire them into the codebase (e.g., use `colorama` in logging handler, use `python-dotenv` for `.env` loading).

29. **Add `tqdm` progress bars** to the orchestrator phase loop and to the multi-target `ThreadPoolExecutor`.

30. **Wire config.yaml to bash modules** - Have `reconx.py` export config values as env vars before calling `subprocess.Popen` for each module, so bash scripts read consistent values.

---

## 5. Impact Matrix

| Change | Effort | Speed Gain | Risk |
| :--- | :--- | :--- | :--- |
| Streaming subprocess | Medium | **3-5x perceived** (real-time output) | Low |
| Batched DB transactions | Low | **10-50x** for bulk inserts | Low |
| Fix FFUF parser bug | Low | N/A (correctness fix, was losing all ffuf data) | None |
| Remove Singleton | Low | N/A (correctness fix) | Low |
| Fix bulk insert semantics | Low | N/A (correctness fix, was losing alive-host updates) | Low |
| Parallelize bash loops | Medium | **3-8x** for Phases 2-4 | Medium |
| Consolidate Nuclei to 1 pass | Low | **3-5x** for Phase 4 Nuclei | Low |
| Streaming file parsers | Medium | **2-5x** memory reduction | Low |
| TEST_MODE | Medium | **Infinite** (enables development) | None |
| Pre-compile regexes | Low | **1.5-2x** for parser hot loops | None |
| Config.yaml loading | Low | N/A (maintainability) | None |

---

## 6. Master Prompt for Developer

*Copy the block below and feed it to an AI Developer to generate the refactored code:*

> **Role:** Senior Python/Bash Developer specializing in security tooling and async I/O.
>
> **Context:** You are refactoring ReconX, a reconnaissance framework that orchestrates 50+ external tools via bash subprocess calls. The codebase has 4 Python files (`reconx.py`, `db/database.py`, `parsers/parser.py`, `query.py`) and 4 bash modules (`modules/01_discovery.sh` through `04_vuln.sh`).
>
> **Task:** Refactor the codebase according to the specification in `CODE_AUDIT_REFACTORING_SPEC.md`. Prioritize in this order:
> 1. Fix the 5 critical bugs (FFUF parser, Singleton, bulk insert, SQL injection, mutable default)
> 2. Implement TEST_MODE with `--test` flag and hardcoded mock data
> 3. Replace `subprocess.run(capture_output=True)` with `subprocess.Popen` streaming
> 4. Batch DB transactions (wrap `executemany` in `BEGIN`/`COMMIT`)
> 5. Load `config.yaml` with `pyyaml` and `.env` with `python-dotenv`
> 6. Replace `print()` with Python `logging` module + `tqdm` progress bars
> 7. Parallelize bash serial loops with `xargs -P` or background jobs
> 8. Consolidate 5 Nuclei invocations into 1
> 9. Extract shared bash utilities to `lib/common.sh`
> 10. Add pytest test suite
>
> **Key Tech:** `subprocess.Popen` for streaming, `pyyaml` for config, `tqdm` for progress, `logging` for structured logs, `xargs -P` for bash parallelism, `pytest` for testing.
>
> **Constraints:**
> - Implement a `TEST_MODE` variable. If `--test` is passed or `TEST_MODE=true` env var is set, use hardcoded mock data from `tests/mock_data.py`. If False, use real inputs.
> - Do NOT change the external tool invocation signatures in bash (the tools themselves are third-party).
> - Preserve the 4-phase sequential architecture (phases depend on each other).
> - Maintain backward compatibility with existing `reconx.db` schema.
> - All existing CLI flags must continue to work.
>
> **Output:** Provide the full, modified files. For each file, show the complete updated version.

---

## Appendix A: File Inventory and Line References

| File | Lines | Key Issues (line numbers) |
| :--- | :--- | :--- |
| `reconx.py` | 587 | L133 (blocking subprocess), L456 (mutable default), L68-76 (eager parser init), no config.yaml load |
| `db/database.py` | 555 | L22-28 (broken Singleton), L209-215 (commit-per-statement), L379-382 (INSERT OR IGNORE drops updates), L504-540 (8 separate stat queries) |
| `parsers/parser.py` | 501 | L18-25 (memory bomb read_lines), L28-51 (double memory read_json), L298-310 (FFUF bug), L253-292 (duplicated URL parsers), L59/66 (uncompiled regex) |
| `query.py` | 276 | L200 (SQL injection in export_csv) |
| `modules/01_discovery.sh` | 712 | L372 (`local` outside function) |
| `modules/02_intel.sh` | 591 | L199-227 (serial DNS), L242-247 (serial RustScan), L281-307 (serial Nmap), L337-342 (serial Shodan) |
| `modules/03_content.sh` | 527 | L286-294 (serial FFUF), L306-313 (serial Feroxbuster), L325-332 (serial Dirsearch), L363-372 (serial LinkFinder) |
| `modules/04_vuln.sh` | 539 | L134-175 (5x redundant Nuclei runs), L245-252 (xargs parallelism inconsistent) |
| `config.yaml` | 221 | Never loaded by any code |
| `requirements.txt` | 26 | 6 unused dependencies |
