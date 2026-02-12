# ReconX Project: Full Structure & Code-by-Code File Explanation

This document describes the **project structure** first, then **every code/script file** and what it does in the pipeline.

---

## 1. Project Structure

```
kali-ASM-main/
├── reconx.py                 # Main orchestrator (entry point)
├── query.py                  # Database query CLI
├── config.yaml               # Configuration (phases, tools, API keys, timeouts)
├── requirements.txt          # Python dependencies
├── .gitignore                # Git ignore rules
├── install.sh                # Full tool installation (system + Go/Rust/Python tools)
├── setup.sh                  # Quick setup (dirs, pip, .env, permissions)
├── apply_fixes.sh            # Applies security/reliability fixes (backups + summary)
│
├── db/                       # Database layer
│   ├── __init__.py           # Package marker (empty)
│   └── database.py           # SQLite manager (WAL, thread-local, CRUD)
│
├── parsers/                  # Tool output → structured data
│   ├── __init__.py           # Package marker (empty)
│   └── parser.py             # All parser classes + URL_TOOL_PARSERS map
│
├── modules/                  # Bash executors (one per phase)
│   ├── 01_discovery.sh       # Phase 1: subdomains, DNS, HTTP, cloud
│   ├── 02_intel.sh           # Phase 2: ports, OSINT, takeover, leaks
│   ├── 03_content.sh         # Phase 3: URLs, dir bruteforce, JS, API
│   ├── 04_vuln.sh            # Phase 4: Nuclei, XSS, SQLi, CORS, etc.
│   └── 01_discovery.sh.backup # Backup (ignore in pipeline)
│
├── lib/                      # Shared Bash helpers
│   └── common.sh             # log_*, safe_cat, safe_grep, check_disk_space, run_tool
│
├── examples/
│   └── quick_start.sh        # Prints usage examples (no execution)
│
├── tests/                    # Unit + integration tests
│   ├── __init__.py
│   ├── mock_data.py         # Mock tool outputs (subfinder, httpx, nmap, etc.)
│   ├── test_database.py     # DB init, bulk inserts, stats, tool_runs
│   ├── test_parsers.py      # Parser output correctness
│   └── test_integration.py  # Full scan in --test mode
│
├── output/                   # Created at runtime: per-target scan results
├── logs/                     # Created at runtime: reconx.log
└── (docs: README.md, OVERVIEW.md, PROJECT_SUMMARY.md, LICENSE, etc.)
```

**Pipeline flow (high level):**
1. User runs `reconx.py -t example.com` (or `-f file`, `-p phases`).
2. `reconx.py` loads config, creates `ReconX`, calls `run()`.
3. For each target, `scan_target()` runs phases 1→4: for each phase it runs the corresponding `modules/0N_*.sh` with `(target, output_dir)`, then parses that phase’s output with `parsers/parser.py` and writes to the DB via `db/database.py`.
4. Results are queryable via `query.py` or direct SQLite.

---

## 2. File-by-File Explanation

### 2.1 `reconx.py` — Main Orchestrator

**Role:** Entry point. Parses CLI, loads config, runs phases per target (single or multi-threaded), parses outputs, writes to DB, prints stats.

- **Imports:** argparse, subprocess, threading, logging, Path, ThreadPoolExecutor, dotenv, yaml, tqdm, DatabaseManager, all parser classes and `URL_TOOL_PARSERS`.
- **`Colors`:** ANSI codes for terminal (HEADER, BLUE, GREEN, RED, etc.).
- **`ColorFormatter`:** Log formatter that adds `[+]`/`[-]`/`[!]` and colors by level.
- **`ReconX.__init__`:**
  - Stores targets, output_dir, test_mode.
  - Loads `config.yaml` via `_load_config()`.
  - Reads threads, phase timeouts from config/env (e.g. `RECONX_PHASE1_TIMEOUT`).
  - Creates `DatabaseManager(db_path)`, sets `modules_dir`, `continue_on_fail`, creates output dir, sets up logging, instantiates all parsers (SubdomainParser, HttpParser, DnsParser, PortParser, UrlParser, DirectoryParser, VulnerabilityParser, LeakParser, TakeoverParser).
- **`_load_config()`:** Reads `config.yaml`, returns dict (empty if missing).
- **`_setup_logging()`:** Creates `logs/`, logger `reconx`, console handler (INFO, colored), file handler (DEBUG, RotatingFileHandler), avoids duplicate handlers.
- **`banner()`:** Prints ASCII ReconX banner.
- **`log_phase()`:** Prints a blue separator and phase title.
- **`phase1_outputs_ok()`:** Returns True only if `phase1_discovery/` has `all_subdomains.txt`, `resolved_subdomains.txt`, `alive_hosts.txt` (used to decide whether to re-run Phase 1 when DB says done but files are missing).
- **`run_module()`:** Runs a Bash module: `subprocess.Popen([script_path, target, str(output_dir)])`, streams stdout to console, drains stderr in a daemon thread to logger, waits with phase timeout; on timeout kills process. Returns True on exit 0, False otherwise.
- **`parse_phase1_output()`:** Reads `phase1_discovery/`: parses `all_subdomains.txt`, `passive_subdomains.txt`, `active_subdomains.txt` with SubdomainParser; `httpx_alive.json` with HttpParser (or fallback `alive_hosts.txt`); `dnsx_resolved.json` with DnsParser. Calls `db.insert_subdomains_bulk()` for all.
- **`parse_phase2_output()`:** Reads `phase2_intel/`: Nmap XML and RustScan ports → PortParser → `insert_ports_bulk`; Subjack → TakeoverParser → `insert_vulnerabilities_bulk`; Gitleaks JSON → LeakParser → `insert_leaks_bulk`.
- **`parse_phase3_output()`:** Reads `phase3_content/urls/` using `URL_TOOL_PARSERS` (gau, waybackurls, hakrawler, katana, spideyx, gospider), and `phase3_content/bruteforce/ffuf_all.json`, `javascript/secretfinder_secrets.txt`, `linkfinder_endpoints.txt`; inserts URLs and leaks.
- **`parse_phase4_output()`:** Reads `phase4_vulnscan/`: Nuclei JSON, Dalfox, SQLMap, Corsy → VulnerabilityParser → `insert_vulnerabilities_bulk`.
- **`scan_target_test_mode()`:** For `--test`: uses `tests.mock_data.MOCK_FILES` to write mock files into target dir (e.g. subfinder → `all_subdomains.txt`, httpx → `httpx_alive.json`, nmap → `phase2_intel/ports/nmap_all.xml`, etc.), then calls the same `parse_phase*_output()` and `db.update_phase()` so parsing/DB path is identical to production.
- **`scan_target()`:** Normal mode: creates target dir, `db.init_target(target)`, loops phases 1–4 with tqdm; for each phase checks progress (and for Phase 1 re-runs if outputs missing), runs module with `run_module()`, then parse and `update_phase()`. Sets `success = False` on module failure but can continue if `continue_on_fail`.
- **`print_statistics()`:** Calls `db.get_stats(target)` and prints subdomains, alive hosts, URLs, ports, leaks, vulns, critical/high counts.
- **`run()`:** Prints banner and logs; if one target runs `scan_target` then stats; else uses ThreadPoolExecutor to run `scan_target` per target; at end prints total time and final statistics for all targets.
- **`main()`:** Argparse: `-t`/`-f`, `-o`, `-d`, `-p`, `-T`, `--resume`, `--test`. Builds targets list, parses phases, validates phases in [1,2,3,4], constructs ReconX, runs `run(phases)`, on exit calls `reconx.db.close()`.

---

### 2.2 `db/database.py` — Database Manager

**Role:** Single place for all SQLite access. Uses WAL mode and thread-local connections so multiple threads can read/write safely. Creates schema and provides CRUD and stats.

- **`DatabaseManager.__init__`:** Stores `db_path`, creates `threading.local()`, calls `_init_database()`.
- **`_get_connection()`:** Thread-local SQLite connection; enables WAL, NORMAL synchronous, cache_size, temp_store; row_factory = sqlite3.Row.
- **`_init_database()`:** Creates tables: `scan_progress` (target, phase1_done..phase4_done, phase*_partial, started_at, updated_at); `tool_runs` (target, phase, tool_name, command, started_at, completed_at, exit_code, status, output_file, records_found, etc.); `acquisitions`, `subdomains`, `ports`, `urls`, `leaks`, `vulnerabilities`, `infrastructure` with UNIQUE constraints and indexes.
- **Execute helpers:** `execute()`, `executemany()`, `fetchone()`, `fetchall()`.
- **Scan progress:** `init_target()`, `update_phase()`, `get_progress()`.
- **Tool runs:** `start_tool_run()`, `complete_tool_run()`, `get_tool_runs()`, `get_failed_tools()`, `get_successful_tools()`.
- **Inserts:** `insert_acquisition(s)_bulk`, `insert_subdomain(s)_bulk` (ON CONFLICT DO UPDATE to merge ip, is_alive, status_code, source_tools), `insert_port(s)_bulk`, `insert_url(s)_bulk`, `insert_leak(s)_bulk`, `insert_vulnerability(s)_bulk`, `insert_infrastructure()`.
- **Getters:** `get_alive_hosts()`, `get_all_subdomains()`.
- **`get_stats()`:** Single query with subqueries for counts: subdomains, alive_hosts, urls, vulnerabilities, critical_vulns, high_vulns, leaks, open_ports.
- **`close()`:** Closes thread-local connection.

---

### 2.3 `parsers/parser.py` — Tool Output Parsers

**Role:** Turn tool-specific output (text, JSON, JSONL, XML) into lists of dicts that match DB columns (host, url, port, severity, etc.).

- **`OutputParser` (base):** `read_lines`, `iter_lines`, `iter_jsonl`, `read_json` (array or JSONL), `extract_domain`, `is_valid_subdomain`; compiled regexes for domain, subdomain, URL.
- **`SubdomainParser`:** `parse_generic_list()` (one host per line, extract_domain + validate), `parse_amass` (JSON or list), `parse_subfinder`/`parse_assetfinder`/`parse_sublist3r`/`parse_subdominator` (delegate to generic list).
- **`HttpParser`:** `parse_httpx()` (JSONL: host/url, status_code, `a` → ip, is_alive=True); `parse_subprober()` (line format URL [CODE]).
- **`DnsParser`:** `parse_dnsx()` (JSONL: host, `a` → ip).
- **`PortParser`:** `parse_nmap_xml()` (ET.parse, host/address/port/state=open, service name/version); `parse_rustscan()` (lines with "Open IP:port" or "host -> [ports]").
- **`UrlParser`:** `parse_url_list()` (one http(s) URL per line, source_tool); `parse_gau`/`waybackurls`/`hakrawler`/`katana`; `parse_spideyx`/`parse_gospider` (regex URL extraction).
- **`URL_TOOL_PARSERS`:** Map filename → tool name (gau.txt→gau, waybackurls.txt→waybackurls, etc.) used by Phase 3 parsing.
- **`DirectoryParser`:** `parse_ffuf()` (JSON with results[].url), `parse_feroxbuster()`/`parse_dirsearch()` (regex status + URL).
- **`VulnerabilityParser`:** `parse_nuclei()` (JSONL: info.name, severity, host, cve from classification); `parse_dalfox()` (lines with [V]/VULN + URL); `parse_sqlmap()` (URL: + vulnerable); `parse_corsy()` (vulnerable/misconfigured + URL).
- **`LeakParser`:** `parse_gitleaks()` (JSON: File, RuleID, Secret → leak_type, url, info, severity); `parse_secretfinder()`/`parse_linkfinder()` (URL or line).
- **`TakeoverParser`:** `parse_subjack()` (vulnerable/takeover + subdomain in brackets).
- **`get_parser(tool_name)`:** Returns the right parser instance by name.

---

### 2.4 `query.py` — Database Query CLI

**Role:** Command-line interface to list targets, show summaries, subdomains, vulns, leaks, ports, and export tables to CSV.

- **`ALLOWED_TABLES`:** Whitelist for `--export` (subdomains, vulnerabilities, leaks, ports, urls) to avoid SQL injection.
- **`ReconXQuery.__init__`:** Creates DatabaseManager with given db path.
- **`list_targets()`:** SELECT DISTINCT target FROM scan_progress; prints count and list.
- **`target_summary()`:** get_stats + get_progress; prints phase completion and stat table (tabulate).
- **`show_subdomains()`:** Optional alive_only filter; prints table Alive, Host, IP, Status, Source.
- **`show_vulnerabilities()`:** Optional severity filter; prints Severity, Tool, Host, Name, CVE (with emoji for critical/high/medium).
- **`show_leaks()`:** leak_type, url, info, severity.
- **`show_ports()`:** host, port, protocol, service, version.
- **`export_csv()`:** Checks table in ALLOWED_TABLES, SELECT * FROM table WHERE target=?, writes CSV with DictWriter.
- **`main()`:** Argparse for -d, -t, --list, --summary, --subdomains, --alive-only, --vulns, --severity, --leaks, --ports, --export, -o; if --list then list_targets; if -t then summary by default and optional subdomains/vulns/leaks/ports/export; finally db.close().

---

### 2.5 `config.yaml` — Configuration

**Role:** Central config for ReconX (no code logic; read by reconx.py).

- **general:** output_dir, database, threads, timeout, user_agent.
- **api_keys:** shodan, censys_id/secret, github, securitytrails, pastebin (values like `${SHODAN_API_KEY}` for env substitution).
- **phase1_discovery:** enabled; subdomain_tools list; dns_resolution (tool, timeout); http_validation (tool, threads, timeout); active_discovery (enabled, wordlist).
- **phase2_intel:** port_scanning (fast/deep, nmap_flags), osint (shodan, censys), takeover_detection, repo_scanning.
- **phase3_content:** archive_crawling (tools, max_urls), directory_bruteforce (tools, wordlist, max_targets), js_analysis, pastebin, api_testing.
- **phase4_vulnscan:** nuclei (severity, tags, rate_limit), xss, sqli, cors, additional (nikto, wpscan, etc.), ssl_tls.
- **logging:** level, file, console.
- **output:** json, html_report, csv_export.
- **performance:** max_memory, cache_enabled.
- **notifications:** slack/discord/email (optional).
- **filters:** exclude_extensions, exclude_status_codes, exclude_patterns.

---

### 2.6 `lib/common.sh` — Shared Bash Utilities

**Role:** Sourced by all module scripts. Provides logging and safe file/disk helpers.

- **Colors:** RED, GREEN, YELLOW, NC.
- **`log_info` / `log_error` / `log_warn`:** Echo with [+]/[-]/[!] and color.
- **`safe_cat output_file input1 input2 ...`:** Concatenates only existing non-empty inputs into output_file; never fails (exit 0).
- **`safe_grep`:** Runs grep with `|| true` so no exit 1 on no match.
- **`check_disk_space dir`:** Uses df; if free < MIN_DISK_MB (default 1024) logs error and returns 1.
- **`tool_supports_flag tool flag`:** Returns 0 if tool’s help mentions flag.
- **`run_tool cmd...`:** Runs command, stderr suppressed, always exit 0.
- **Exports:** All of the above functions are exported for subshells.

---

### 2.7 `modules/01_discovery.sh` — Phase 1: Discovery & Enumeration

**Role:** Subdomain discovery (horizontal + vertical), DNS resolution, HTTP validation, optional ASN/cloud checks. Writes into `$OUTPUT_DIR/phase1_discovery/`.

- **Args:** TARGET, OUTPUT_DIR. Validates target with regex. Creates phase dir. Sources lib/common.sh.
- **Tunables:** Many RECONX_* env vars (WHOIS_TIMEOUT, AMASS_*, SUBLIST3R_*, SUBFINDER_*, DNSX_*, HTTPX_*, etc.).
- **Local `run_tool` override:** Runs a command with timeout; tracks TOOLS_SUCCESS/TOOLS_FAILED/TOOLS_SKIPPED; skips if tool not in PATH.
- **1A Horizontal:** whois, amass intel (or enum passive), getSubsidiaries if present.
- **1B Vertical:** Parallel jobs: Sublist3r, Amass enum, Assetfinder, Subfinder, Subdominator, crt.sh (curl+jq), CertSpotter, ct-monitor, SecurityTrails (if API key). Merge into passive_subdomains.txt, filter valid domains.
- **1C Active:** If passive results exist: Dnsbruter, Dnsprober; merge into active_subdomains.txt.
- **Merge:** passive + active → all_subdomains.txt, sort -u.
- **1D ASN:** asnmap → CIDRs; mapcidr → IP list (asn_ips.txt).
- **1E DNS:** dnsx on all_subdomains.txt → dnsx_resolved.json, extract hosts → resolved_subdomains.txt.
- **1F HTTP:** resolved + ASN IPs → httpx_targets.txt; httpx → httpx_alive.json, extract URLs → alive_hosts.txt (with fallbacks).
- **1G Cloud:** Build keywords from target + subdomains; run cloud_enum, s3scanner, goblob, gcpbucketbrute if available; merge cloud assets.
- **End:** Summary, touch .completed, exit 0 so pipeline continues even if no subdomains.

---

### 2.8 `modules/02_intel.sh` — Phase 2: Intelligence & Infrastructure

**Role:** Validate hosts, port scan (RustScan + Nmap), OSINT (Shodan, ShodanX, Censys, Google dorks, ASN), subdomain takeover (Subjack, SubOver), repo/secret scanning (Gitleaks, GitHunt, TruffleHog, git-secrets). Reads Phase 1 alive/resolved; writes under `phase2_intel/`.

- **Args:** TARGET, OUTPUT_DIR. Uses Phase 1 alive_hosts.txt (fallback to resolved_subdomains). Sources common.sh.
- **2A Validation:** SubProber on alive hosts → subprober_validated.txt; union with alive → scan_hosts.txt.
- **2B Ports:** Extract hostnames/IPs from scan_hosts; optional dnsx resolution → targets.txt. RustScan on all targets → rustscan_ports.txt. Nmap -sV -sC on top hosts (capped), using RustScan ports if available; output nmap_all.xml, nmap_all.txt. check_disk_space before Nmap.
- **2C OSINT:** Shodan host lookup per host; ShodanX domain/subdomain modes; GoogleDorker with built-in dork list; Censys per host; ASN info from whois on IPs from Phase 1 dnsx.
- **2D Takeover:** Subjack on all_subdomains.txt; SubOver if available.
- **2E Leaks:** Gitleaks (local .git or gh repo list + clone); GitHunt (target + GITHUB_TOKEN); TruffleHog (local git / GitHub org); git-secrets if .git.
- **End:** Summary, touch .completed, exit 0.

---

### 2.9 `modules/03_content.sh` — Phase 3: Deep Web & Content Discovery

**Role:** URL discovery (archives + crawlers), directory/file brute-force, JavaScript analysis, optional Pastebin/API. Reads Phase 1 alive_hosts; writes under `phase3_content/`.

- **Args:** TARGET, OUTPUT_DIR. Requires Phase 1 alive_hosts.txt. Sources common.sh.
- **3A URL discovery:** targets = all_subdomains + root domain. Parallel: GAU, waybackurls, SpideyX (crawler), gospider, hakrawler, Katana. Merge → all_urls.txt; filter .js/.json → javascript_files.txt. Optional SpideyX jsscrapy on JS URLs.
- **3B Bruteforce:** Wordlist (SecLists or dirb or minimal built-in). Top 20 alive hosts. FFUF, Feroxbuster, Dirsearch (with rate limiting); outputs under bruteforce/.
- **3C JavaScript:** LinkFinder, SecretFinder, JSScanner on JS files; outputs in javascript/.
- **3D Pastebin / API:** PasteHunter, Pastebin API if configured; Newman, Kiterunner, Arjun for API discovery (when enabled).
- **End:** Summary, touch .completed.

---

### 2.10 `modules/04_vuln.sh` — Phase 4: Vulnerability Scanning

**Role:** Run vulnerability scanners on alive hosts and Phase 3 URLs. Writes under `phase4_vulnscan/`.

- **Args:** TARGET, OUTPUT_DIR. Requires Phase 1 alive_hosts. Builds scan_urls.txt (alive with https:// + head of Phase 3 all_urls). Sources common.sh, exports log_*.
- **4A Nuclei:** nuclei -update-templates; one run with severity critical,high,medium,low,info and tags cve,misconfiguration,config; output nuclei_all.json.
- **4B XSS:** Dalfox on parameterized URLs from Phase 3; XSStrike on first 20 if available.
- **4C SQLi:** SQLMap on parameterized URLs (batch, level 1 risk 1), parallel via run_parallel_from_file.
- **4D CORS:** Corsy on scan_urls.txt.
- **4E Misc:** Nikto (top hosts), WPScan (WordPress), Wapiti, CMSmap, Retire.js; testssl/SSLyze for SSL (top hosts).
- **End:** Summary, touch .completed.

---

### 2.11 `install.sh` — Full Installation Script

**Role:** Run as root to install system packages, Python venv, Go/Rust/Python tools, wordlists, and PATH. Used for a full ReconX toolchain.

- **Checks:** Must run as root. Detects OS (Kali/Debian/Ubuntu or Arch).
- **System packages:** apt/pacman install of python3, git, jq, nmap, masscan, nikto, sqlmap, chromium, go, docker, etc.
- **Python:** Creates venv under /opt/reconx-tools/venv; installs from requirements.txt; optional wrappers in /usr/local/bin.
- **Go tools:** go install for subfinder, amass, httpx, dnsx, nuclei, katana, etc. (long list).
- **Rust:** rustscan, feroxbuster via cargo if rust installed.
- **Git clones:** Optional /opt installs for Sublist3r, Subdominator, Gitleaks, etc.
- **Wordlists:** SecLists clone if missing.
- **PATH:** Instructions or export for GOPATH/bin and cargo bin.
- **Verification:** Lists critical tools and reports missing ones.

---

### 2.12 `setup.sh` — Quick Setup

**Role:** Non-root prep in the ReconX repo: dirs, pip install, .env from template, chmod, tool check, DB test.

- **Requires:** Run from directory containing reconx.py.
- **Creates:** output/, logs/.
- **pip:** pip3 install -r requirements.txt.
- **.env:** Copy .env.example to .env if missing; remind user to add API keys.
- **chmod +x** on reconx.py, query.py, install.sh, modules/*.sh.
- **Checks:** python3, bash, sqlite3; subfinder, amass, httpx, nuclei, nmap.
- **DB test:** Python import DatabaseManager, create test db, remove.
- **Go:** Warn if Go missing or GOPATH not set.
- **Prints:** Next steps (edit .env, source .env, optionally install.sh, run reconx).

---

### 2.13 `apply_fixes.sh` — Security/Reliability Fixes

**Role:** Documented fix application: backup key files then print what was “fixed” (no actual code patching in script).

- **Requires:** Run from ReconX root (reconx.py present).
- **Backup:** backups/YYYYMMDD_HHMMSS/ with copies of modules/*.sh, reconx.py, db/database.py.
- **Prints:** Summary of DB schema changes, 01_discovery.sh changes (no set -e, error handling, timeouts, etc.), and “remaining work” for modules 02–04 and reconx best-effort mode. Refers to FIXES_APPLIED.md.

---

### 2.14 `examples/quick_start.sh` — Usage Examples

**Role:** Prints example commands and short descriptions; creates a sample targets_example.txt. Does not run scans.

- Echoes examples: single target, phase-only, multiple targets, from file, query.py --summary/--subdomains/--vulns, and sample sqlite3 commands. Ends with pointer to README and reconx.py -h.

---

### 2.15 `tests/mock_data.py` — Mock Tool Outputs

**Role:** Provides in-memory and file-content mock data so parsers and integration tests don’t need real tools.

- **Constants:** MOCK_SUBDOMAINS, MOCK_ALIVE_HOSTS, MOCK_PORTS, MOCK_URLS, MOCK_VULNS, MOCK_LEAKS.
- **Raw strings:** MOCK_SUBFINDER_OUTPUT, MOCK_HTTPX_OUTPUT, MOCK_NMAP_XML, MOCK_FFUF_OUTPUT, MOCK_NUCLEI_OUTPUT, MOCK_GAU_OUTPUT, MOCK_KATANA_OUTPUT, MOCK_TRUFFLEHOG_OUTPUT.
- **`MOCK_FILES`:** Dict mapping filename → content (subfinder.txt, httpx.jsonl, nmap_all.xml, ffuf_all.json, nuclei_all.json, gau.txt, katana.txt, trufflehog.txt). Used by test_parsers (write to temp dir) and by reconx test mode (write to phase dirs).

---

### 2.16 `tests/test_database.py` — Database Unit Tests

**Role:** Verify DatabaseManager with temp DB files.

- **TestDatabaseInit:** init_target creates progress row; fresh DB has zero stats.
- **TestDifferentDbPaths:** Two DatabaseManager instances use separate DB files (no accidental singleton sharing).
- **TestInsertSubdomainsBulk:** Bulk insert and ON CONFLICT merge (e.g. is_alive update).
- **TestPortsUrlsLeaksVulns:** insert_ports_bulk, insert_urls_bulk, insert_leaks_bulk, insert_vulnerabilities_bulk; get_stats reflects counts.
- **TestToolRuns:** start_tool_run, complete_tool_run; get_tool_runs / get_failed_tools / get_successful_tools.

Uses tests.mock_data for sample records.

---

### 2.17 `tests/test_parsers.py` — Parser Unit Tests

**Role:** Ensure each parser produces the expected structure from mock files.

- **ParserTestBase:** Writes MOCK_FILES into a temp dir before each test.
- **TestSubdomainParser:** parse_subfinder returns list, correct hosts and source_tool.
- **TestHttpParser:** parse_httpx returns alive hosts with is_alive and ip.
- **TestPortParser:** parse_nmap_xml / parse_rustscan return port list with host, port, protocol, service.
- **TestDirectoryParser:** parse_ffuf returns URLs from JSON results.
- **TestVulnerabilityParser:** parse_nuclei returns name, severity, host, cve.
- **TestUrlParser:** parse_url_list / parse_gau return url and source_tool.

---

### 2.18 `tests/test_integration.py` — Integration Tests (Test Mode)

**Role:** Full pipeline test without network: ReconX in test_mode runs all four phases using mock files, then asserts DB state.

- **test_scan_populates_database:** ReconX(test_mode=True).scan_target() → get_stats has subdomains, alive_hosts, urls, open_ports, vulnerabilities > 0.
- **test_scan_progress_marked_complete:** After full scan, phase1_done through phase4_done are True.
- **test_scan_only_selected_phases:** Scan with phases=[1,2] → only phase1_done and phase2_done True.

Uses temp DB and temp output dir; no external tools.

---

### 2.19 `requirements.txt` — Python Dependencies

**Role:** List of pip packages for ReconX.

- pyyaml, python-dotenv (config and .env).
- colorama, tqdm, tabulate (CLI and tables).
- lxml (XML parsing; used by parsers for Nmap).
- SQLite3 is stdlib (no package).

---

### 2.20 `db/__init__.py` and `parsers/__init__.py` — Package Markers

**Role:** Empty files so `db` and `parsers` are Python packages and `from db.database import ...` / `from parsers.parser import ...` work.

---

### 2.21 `.gitignore` — Git Ignore Rules

**Role:** Exclude from version control: __pycache__, *.pyc, venv, *.db and WAL/SHM, logs/, .env, secrets, IDE/OS junk, output/, *.err, pytest/coverage dirs.

---

## 3. Pipeline Summary (Data Flow)

1. **User:** `python3 reconx.py -t example.com -p 1,2,3,4`
2. **reconx.py:** Loads config, creates ReconX, run() → for target: init_target(), then for each phase:
   - Run `modules/0N_*.sh example.com output/example_com/`
   - Parse that phase’s output with parsers/parser.py
   - DB insert (subdomains, ports, urls, leaks, vulnerabilities) and update_phase()
3. **Phase 1** produces: all_subdomains.txt, resolved_subdomains.txt, alive_hosts.txt, httpx_alive.json, dnsx_resolved.json → subdomains table (and alive/status).
4. **Phase 2** produces: ports (nmap_all.xml, rustscan_ports.txt), takeover (subjack), leaks (gitleaks*.json) → ports, vulnerabilities (takeover), leaks.
5. **Phase 3** produces: urls (gau, waybackurls, etc.), bruteforce (ffuf), javascript (secretfinder, linkfinder) → urls, leaks.
6. **Phase 4** produces: nuclei, dalfox, sqlmap, corsy → vulnerabilities.
7. **User:** `python3 query.py -t example.com --summary` or `--vulns --severity critical` or `--export vulnerabilities -o out.csv` reads from the same DB.

This completes the project structure and the code-by-code explanation of every file in the ReconX pipeline.
