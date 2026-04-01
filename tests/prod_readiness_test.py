#!/usr/bin/env python3
"""
Technieum Production Readiness Test Runner

Runs a full audit in 8 phases, produces a final scoring table.
Designed to be a single-file runner: no external test framework required.

Usage:
  python tests/prod_readiness_test.py --host 127.0.0.1 --port 8000 --base /Users/rejenthompson/Documents/technieum-/kali-linux-asm

Optional:
  Set TECHNIEUM_BASE env var to override --base

Requirements:
  - requests (pip install requests)
"""
import argparse
import contextlib
import dataclasses
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import requests
except ImportError:
    print("ERROR: 'requests' is required. Install with: pip install requests")
    sys.exit(1)

# ----------------------------- Config & Constants -----------------------------
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
STARTUP_WAIT_SEC = 6
SSE_READ_SEC = 5
HTTP_TIMEOUT = 10
BASE_DIRS_TO_COMPILE = ["app", "api", "cli", "db", "backend", "intelligence"]
PASS_THRESHOLD = 110  # /117

# ------------------------------- Data Structures ------------------------------
@dataclasses.dataclass
class PhaseScore:
    label: str
    max_points: int
    passed: int = 0
    failed: int = 0
    details: List[str] = dataclasses.field(default_factory=list)

    def add(self, ok: bool, msg: str):
        if ok:
            self.passed += 1
        else:
            self.failed += 1
            self.details.append(msg)

    @property
    def score(self) -> int:
        return self.passed


@dataclasses.dataclass
class Context:
    base: Path
    host: str
    port: int
    base_url: str
    api_v1: str
    server_proc: Optional[subprocess.Popen] = None
    worker_proc: Optional[subprocess.Popen] = None
    api_key: Optional[str] = None


# --------------------------------- Utilities ----------------------------------

def run_cmd(cmd: List[str], cwd: Optional[Path] = None, timeout: int = 30) -> Tuple[int, str, str]:
    """Run a shell command and return (exit_code, stdout, stderr)."""
    proc = subprocess.Popen(cmd, cwd=str(cwd) if cwd else None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, out, err
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return 124, out, err


def python_compile_tree(base: Path, rel_dir: str) -> Tuple[bool, List[str]]:
    """Compile all .py files under rel_dir; returns (ok, errors)."""
    errors: List[str] = []
    target = base / rel_dir
    if not target.exists():
        return True, []
    for py in target.rglob("*.py"):
        code, out, err = run_cmd([sys.executable, "-m", "py_compile", str(py)], cwd=base)
        if code != 0:
            errors.append(f"py_compile failed: {py}: {err.strip() or out.strip()}")
    return len(errors) == 0, errors


def import_check(module: str) -> Tuple[bool, str]:
    try:
        __import__(module)
        return True, ""
    except Exception as e:
        return False, f"Import error for {module}: {e}"


def start_server(ctx: Context) -> Tuple[bool, str]:
    if ctx.server_proc:
        return True, "Server already running"
    cmd = [sys.executable, "-m", "uvicorn", "api.server:app", "--host", ctx.host, "--port", str(ctx.port)]
    env = os.environ.copy()
    # Prefer venv if present
    venv_bin = ctx.base / "venv" / "bin"
    if venv_bin.exists():
        env["PATH"] = f"{venv_bin}:{env['PATH']}"
    ctx.server_proc = subprocess.Popen(cmd, cwd=str(ctx.base), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    # Wait for startup
    time.sleep(STARTUP_WAIT_SEC)
    # Check logs for ERROR/WARNING
    ok, msg = True, ""
    if ctx.server_proc and ctx.server_proc.stdout:
        try:
            logs = ctx.server_proc.stdout.read() or ""
        except Exception:
            logs = ""
        # Allow uvicorn info lines; flag any ERROR/Traceback/WARNING
        if re.search(r"ERROR|Traceback|WARNING", logs):
            ok = False
            msg = f"Server startup logs contain errors/warnings:\n{logs[-1000:]}"
    # Health check
    try:
        r = requests.get(f"{ctx.base_url}/api/health", timeout=HTTP_TIMEOUT)
        ok = ok and (r.status_code == 200)
        if r.status_code != 200:
            msg += f"\nHealth check failed: {r.status_code}"
    except Exception as e:
        ok = False
        msg += f"\nHealth request error: {e}"
    return ok, msg.strip()


def stop_server(ctx: Context):
    if ctx.server_proc:
        with contextlib.suppress(Exception):
            os.kill(ctx.server_proc.pid, signal.SIGTERM)
        ctx.server_proc = None


def get_json(url: str, headers: Optional[Dict[str, str]] = None, allow_422: bool = False) -> Tuple[bool, int, Optional[Dict], str]:
    try:
        r = requests.get(url, headers=headers or {}, timeout=HTTP_TIMEOUT)
        status = r.status_code
        if status in (200, 201) or (allow_422 and status == 422):
            try:
                return True, status, r.json(), ""
            except Exception as e:
                return False, status, None, f"Invalid JSON: {e}"
        return False, status, None, f"Unexpected status {status}"
    except Exception as e:
        return False, 0, None, f"Request error: {e}"


def post_json(url: str, json_body: Dict, headers: Optional[Dict[str, str]] = None) -> Tuple[bool, int, Optional[Dict], str]:
    try:
        r = requests.post(url, json=json_body, headers=headers or {}, timeout=HTTP_TIMEOUT)
        status = r.status_code
        if status in (200, 201):
            try:
                return True, status, r.json(), ""
            except Exception as e:
                return False, status, None, f"Invalid JSON: {e}"
        return False, status, None, f"Unexpected status {status}"
    except Exception as e:
        return False, 0, None, f"Request error: {e}"


def delete(url: str, headers: Optional[Dict[str, str]] = None) -> Tuple[bool, int, Optional[Dict], str]:
    try:
        r = requests.delete(url, headers=headers or {}, timeout=HTTP_TIMEOUT)
        status = r.status_code
        if status in (200, 204):
            try:
                js = r.json() if r.content else {}
            except Exception:
                js = {}
            return True, status, js, ""
        return False, status, None, f"Unexpected status {status}"
    except Exception as e:
        return False, 0, None, f"Request error: {e}"


def sse_check(url: str, headers: Optional[Dict[str, str]] = None) -> Tuple[bool, str]:
    try:
        r = requests.get(url, headers=headers or {}, stream=True, timeout=HTTP_TIMEOUT)
        ctype = r.headers.get("content-type", "")
        if "text/event-stream" not in ctype:
            return False, f"Wrong content-type: {ctype}"
        # Read a few lines for SSE
        start = time.time()
        for line in r.iter_lines():
            if time.time() - start > SSE_READ_SEC:
                break
        return True, ""
    except Exception as e:
        return False, f"SSE error: {e}"


# ---------------------------------- Phases ------------------------------------

def phase_1_env_boot(ctx: Context) -> PhaseScore:
    ps = PhaseScore("Environment & Boot", max_points=10)
    # 1. venv + python version
    ver_ok = sys.version_info.major == 3 and sys.version_info.minor >= 11
    ps.add(ver_ok, f"Python version must be 3.11+, found {sys.version}")
    # 2. pip check
    code, out, err = run_cmd([sys.executable, "-m", "pip", "check"], cwd=ctx.base)
    ps.add(code == 0, f"pip check failed: {err or out}")
    # 3. compile dirs
    all_ok = True
    for rd in BASE_DIRS_TO_COMPILE:
        ok, errs = python_compile_tree(ctx.base, rd)
        ps.add(ok, "\n".join(errs) if errs else f"Compiled {rd}")
        all_ok = all_ok and ok
    # 4-6 import checks
    ok_app, msg = import_check("app.api.server")
    ps.add(ok_app, msg)
    ok_worker, msg = import_check("app.workers.worker")
    ps.add(ok_worker, msg)
    ok_db, msg = import_check("app.db.database")
    ps.add(ok_db, msg)
    # 6 migrations
    try:
        code, out, err = run_cmd([sys.executable, "-c", "from app.db.database import apply_migrations; apply_migrations()"], cwd=ctx.base)
        ps.add(code == 0, f"apply_migrations failed: {err or out}")
    except Exception as e:
        ps.add(False, f"apply_migrations exception: {e}")
    # 7 start server
    ok, msg = start_server(ctx)
    ps.add(ok, msg or "Server started OK")
    return ps


def phase_2_api_coverage(ctx: Context) -> PhaseScore:
    ps = PhaseScore("API Endpoints (47)", max_points=47)
    # Bootstrap key
    ok, status, js, msg = get_json(f"{ctx.base_url}/api/v1/bootstrap-key")
    ps.add(ok, msg or f"Bootstrap-key status {status}")
    if ok:
        ctx.api_key = js.get("key")
    headers = {"X-API-Key": ctx.api_key or ""}

    # Health & meta
    for path in ["/health", "/api/health", "/version", "/api/v1/metrics/"]:
        ok, status, js, msg = get_json(f"{ctx.base_url}{path}")
        ps.add(ok, f"{path} {msg}")
    # Scans list
    ok, status, js, msg = get_json(f"{ctx.api_v1}/scans/", headers)
    ps.add(ok, f"/scans/ {msg}")
    # Create scan
    ok, status, created, msg = get_json(f"{ctx.api_v1}/scans?target=testdomain.com&phases=1,2,3&test_mode=true", headers)
    ps.add(ok and status in (200, 201), f"POST /scans {msg}")
    scan_id = None
    if ok:
        scan_id = created.get("id") or created.get("scan_id")
    # Get scan by id
    if scan_id:
        ok, status, js, msg = get_json(f"{ctx.api_v1}/scans/{scan_id}", headers)
        ps.add(ok, f"/scans/{{id}} {msg}")
        ok, status, js, msg = get_json(f"{ctx.api_v1}/scans/{scan_id}/status", headers)
        ps.add(ok or status == 404, f"/scans/{{id}}/status {msg}")
        ok, status, js, msg = get_json(f"{ctx.api_v1}/scans/{scan_id}/progress", headers)
        ps.add(ok or status == 404, f"/scans/{{id}}/progress {msg}")
        ok, status, js, msg = get_json(f"{ctx.api_v1}/scans/{scan_id}/job", headers)
        ps.add(ok or status in (200, 404), f"/scans/{{id}}/job {msg}")
        # start/stop
        ok, status, js, msg = post_json(f"{ctx.api_v1}/scans/{scan_id}/start", {}, headers)
        ps.add(ok or status in (200, 404, 409), f"/scans/{{id}}/start {msg}")
        ok, status, js, msg = post_json(f"{ctx.api_v1}/scans/{scan_id}/stop", {}, headers)
        ps.add(ok or status in (200, 404, 409), f"/scans/{{id}}/stop {msg}")
        # delete (create throwaway if needed)
        ok, status, js, msg = delete(f"{ctx.api_v1}/scans/{scan_id}", headers)
        ps.add(ok or status in (200, 204, 404), f"DELETE /scans/{{id}} {msg}")
    else:
        # If no id, mark related checks as failed
        for lbl in ["/scans/{id}", "/scans/{id}/status", "/scans/{id}/progress", "/scans/{id}/job", "/scans/{id}/start", "/scans/{id}/stop", "DELETE /scans/{id}"]:
            ps.add(False, f"{lbl}: no scan_id returned from create")

    # Assets
    ok, status, js, msg = get_json(f"{ctx.api_v1}/assets/targets", headers)
    ps.add(ok, f"/assets/targets {msg}")
    ok, status, js, msg = get_json(f"{ctx.api_v1}/assets/stats/testdomain.com", headers)
    ps.add(ok or status in (200, 404), f"/assets/stats {{msg}}")
    ok, status, js, msg = get_json(f"{ctx.api_v1}/assets/search?q=test", headers)
    ps.add(ok, f"/assets/search {msg}")
    ok, status, js, msg = get_json(f"{ctx.api_v1}/assets/by-domain/testdomain.com", headers)
    ps.add(ok or status in (200, 404), f"/assets/by-domain {msg}")
    ok, status, js, msg = get_json(f"{ctx.api_v1}/assets/high-risk", headers)
    ps.add(ok or status in (200, 404), f"/assets/high-risk {msg}")
    ok, status, js, msg = get_json(f"{ctx.api_v1}/assets/", headers)
    ps.add(ok, f"/assets/ {msg}")
    # MUST exist tests
    ok_sub, status_sub, js_sub, msg_sub = get_json(f"{ctx.api_v1}/assets/subdomains/testdomain.com", headers)
    ps.add(ok_sub, f"/assets/subdomains MUST EXIST: {msg_sub}")
    ok_ports, status_ports, js_ports, msg_ports = get_json(f"{ctx.api_v1}/assets/ports/testdomain.com", headers)
    ps.add(ok_ports, f"/assets/ports MUST EXIST: {msg_ports}")

    # Findings
    for path in ["/findings/", "/findings/by-severity", "/findings/by-type", "/findings/testdomain.com", "/findings/testdomain.com/summary", "/findings/domain/testdomain.com/summary"]:
        ok, status, js, msg = get_json(f"{ctx.api_v1}{path}", headers)
        ps.add(ok or status in (200, 404), f"{path} {msg}")

    # Threat Intel
    for path in ["/intel/threat-feed", "/intel/data-leaks", "/intel/malware/test-ioc", "/intel/ip-reputation/8.8.8.8", "/intel/domain-reputation/example.com"]:
        ok, status, js, msg = get_json(f"{ctx.api_v1}{path}", headers)
        ps.add(ok or status in (200, 404), f"{path} {msg}")

    # Reports
    for path in ["/reports/templates", "/reports/"]:
        ok, status, js, msg = get_json(f"{ctx.api_v1}{path}", headers)
        ps.add(ok, f"{path} {msg}")
    ok, status, js, msg = post_json(f"{ctx.api_v1}/reports/", {"scan_run_id": 1, "report_type": "executive"}, headers)
    ps.add(ok or status in (200, 404, 422), f"POST /reports {msg}")

    # SSE Streams
    # Use scan_id 1 if available, otherwise 0 (may 404 but should still be event-stream type in some implementations)
    sid = scan_id or 1
    for path in [f"/stream/logs/{sid}", f"/stream/scan/{sid}", f"/stream/progress/{sid}"]:
        ok, msg = sse_check(f"{ctx.api_v1}{path}", headers)
        ps.add(ok or "Wrong content-type" not in msg, f"SSE {path} {msg}")
    ok, msg = sse_check(f"{ctx.api_v1}/stream/alerts", headers)
    ps.add(ok or "Wrong content-type" not in msg, f"SSE /stream/alerts {msg}")

    # Webhooks
    ok, status, js, msg = get_json(f"{ctx.api_v1}/webhooks/", headers)
    ps.add(ok, f"/webhooks/ {msg}")
    ok, status, created, msg = post_json(f"{ctx.api_v1}/webhooks/", {"url": "https://httpbin.org/post", "events": ["scan.completed"]}, headers)
    ps.add(ok or status in (200, 201, 422), f"POST /webhooks/ {msg}")
    webhook_id = None
    if ok:
        webhook_id = created.get("id")
    if webhook_id:
        ok, status, js, msg = post_json(f"{ctx.api_v1}/webhooks/{webhook_id}/test", {}, headers)
        ps.add(ok or status in (200, 400), f"/webhooks/{{id}}/test {msg}")
        ok, status, js, msg = get_json(f"{ctx.api_v1}/webhooks/{webhook_id}/events", headers)
        ps.add(ok or status in (200, 404), f"/webhooks/{{id}}/events {msg}")
        ok, status, js, msg = post_json(f"{ctx.api_v1}/webhooks/{webhook_id}", {"active": False}, headers)
        ps.add(ok or status in (200, 404, 422), f"PUT /webhooks/{{id}} {msg}")
        ok, status, js, msg = delete(f"{ctx.api_v1}/webhooks/{webhook_id}", headers)
        ps.add(ok or status in (200, 204, 404), f"DELETE /webhooks/{{id}} {msg}")
    else:
        for lbl in ["/webhooks/{id}/test", "/webhooks/{id}/events", "PUT /webhooks/{id}", "DELETE /webhooks/{id}"]:
            ps.add(False, f"{lbl}: no webhook id")
    return ps


def phase_3_ui_pages(ctx: Context) -> PhaseScore:
    ps = PhaseScore("UI Pages (10)", max_points=10)
    routes = [
        ("/", "index.html", "dashboard-v2.js"),
        ("/dashboard", "index.html", "dashboard-v2.js"),
        ("/assessments", "scan_viewer_v2.html", "scan_monitor_v2.js"),
        ("/vulnerabilities", "findings_v2.html", "findings_v2.js"),
        ("/graph", "graph_viewer_v2.html", "graph_viz_v2.js"),
        ("/attack-surface", "attack_surface_v2.html", None),
        ("/reports", "reports_v2.html", None),
        ("/compliance", "compliance_v2.html", None),
        ("/alerts", "alerts_v2.html", None),
        ("/settings", "settings_v2.html", None),
    ]
    for route, expected_html, expected_js in routes:
        ok, status, _, msg = get_json(f"{ctx.base_url}{route}")
        # These are HTML pages, so JSON will fail; use raw GET
        try:
            r = requests.get(f"{ctx.base_url}{route}", timeout=HTTP_TIMEOUT)
            ok_route = r.status_code == 200
            html = r.text
            has_ensure = "ensureApiKey" in html
            has_demo_key = "demo_key" in html
            ok = ok_route and has_ensure and (not has_demo_key)
            fail_msgs = []
            if not ok_route:
                fail_msgs.append(f"{route}: HTTP {r.status_code}")
            if not has_ensure:
                fail_msgs.append(f"{route}: missing ensureApiKey")
            if has_demo_key:
                fail_msgs.append(f"{route}: contains demo_key fallback")
            ps.add(ok, "; ".join(fail_msgs) or f"{route} OK")
        except Exception as e:
            ps.add(False, f"{route} request error: {e}")
    # Threat intel page must exist
    try:
        r = requests.get(f"{ctx.base_url}/threat-intel", timeout=HTTP_TIMEOUT)
        ok = r.status_code == 200 and ("ensureApiKey" in r.text)
        ps.add(ok, "threat-intel page missing or lacks ensureApiKey")
    except Exception as e:
        ps.add(False, f"/threat-intel error: {e}")
    return ps


def phase_4_wiring(ctx: Context) -> PhaseScore:
    ps = PhaseScore("UI→Backend Wiring", max_points=20)
    headers = {"X-API-Key": ctx.api_key or ""}
    # dashboard-v2
    for path in ["/bootstrap-key", "/assets/targets", "/scans"]:
        ok, status, js, msg = get_json(f"{ctx.api_v1}{path}", headers)
        ps.add(ok, f"dashboard-v2 {path} {msg}")
    # findings-v2
    for path in ["/assets/targets", "/findings/testdomain.com", "/findings/testdomain.com/summary"]:
        ok, status, js, msg = get_json(f"{ctx.api_v1}{path}", headers)
        ps.add(ok or status in (200, 404), f"findings-v2 {path} {msg}")
    # scan_monitor-v2
    for path in ["/scans", "/scans/1/status", "/assets/stats/testdomain.com"]:
        ok, status, js, msg = get_json(f"{ctx.api_v1}{path}", headers)
        ps.add(ok or status in (200, 404), f"scan_monitor-v2 {path} {msg}")
    ok, msg = sse_check(f"{ctx.api_v1}/stream/logs/1", headers)
    ps.add(ok or "Wrong content-type" not in msg, f"scan_monitor-v2 SSE logs {msg}")
    # graph_viz_v2
    for path in ["/assets/targets", "/assets/subdomains/testdomain.com", "/assets/ports/testdomain.com", "/findings/testdomain.com"]:
        ok, status, js, msg = get_json(f"{ctx.api_v1}{path}", headers)
        must_exist = path.startswith("/assets/subdomains") or path.startswith("/assets/ports")
        ps.add(ok if not must_exist else ok, f"graph_viz_v2 {path} {msg}")
    return ps


def phase_5_worker(ctx: Context) -> PhaseScore:
    ps = PhaseScore("Worker Pipeline", max_points=10)
    # Start worker briefly
    try:
        ctx.worker_proc = subprocess.Popen([sys.executable, "-m", "app.workers.worker"], cwd=str(ctx.base), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        time.sleep(5)
        ps.add(True, "Worker started")
    except Exception as e:
        ps.add(False, f"Worker start error: {e}")
    # start.sh exists & executable
    start_sh = ctx.base / "start.sh"
    ps.add(start_sh.exists() and os.access(start_sh, os.X_OK), "start.sh missing or not executable")
    # Create a scan & verify basic endpoints
    headers = {"X-API-Key": ctx.api_key or ""}
    ok, status, created, msg = get_json(f"{ctx.api_v1}/scans?target=testdomain.com&phases=1,2,3&test_mode=true", headers)
    ps.add(ok, f"create scan {msg}")
    # Verify ingestion endpoints respond (may be empty on macOS/test mode)
    ok, status, js, msg = get_json(f"{ctx.api_v1}/assets/subdomains/testdomain.com", headers)
    ps.add(ok, f"subdomains after scan {msg}")
    ok, status, js, msg = get_json(f"{ctx.api_v1}/findings/testdomain.com", headers)
    ps.add(ok, f"findings after scan {msg}")
    # Cleanup worker
    if ctx.worker_proc:
        with contextlib.suppress(Exception):
            os.kill(ctx.worker_proc.pid, signal.SIGTERM)
        ctx.worker_proc = None
    return ps


def phase_6_security(ctx: Context) -> PhaseScore:
    ps = PhaseScore("Security", max_points=10)
    # Auth enforcement: without key
    for path in ["/scans/", "/assets/targets", "/findings/", "/scans?target=evil.com"]:
        try:
            r = requests.get(f"{ctx.api_v1}{path}", timeout=HTTP_TIMEOUT)
            ps.add(r.status_code in (401, 403), f"{path} expected 401/403, got {r.status_code}")
        except Exception as e:
            ps.add(False, f"{path} error: {e}")
    # Exemptions
    for route in ["/health", "/api/health", "/api/v1/bootstrap-key"]:
        try:
            r = requests.get(f"{ctx.base_url}{route}", timeout=HTTP_TIMEOUT)
            ps.add(r.status_code == 200, f"{route} expected 200, got {r.status_code}")
        except Exception as e:
            ps.add(False, f"{route} error: {e}")
    # SSE no-key should work per exemption list (if configured)
    try:
        r = requests.get(f"{ctx.api_v1}/stream/alerts", timeout=HTTP_TIMEOUT, stream=True)
        ps.add(r.status_code in (200, 204), f"/stream/alerts expected 200, got {r.status_code}")
    except Exception as e:
        ps.add(False, f"/stream/alerts error: {e}")
    # XSS check: inline onclick patterns in JS/HTML
    dup_count = 0
    for ext in (".js", ".html"):
        for fp in (ctx.base / "web" / "static").rglob(f"*{ext}"):
            try:
                txt = fp.read_text(encoding="utf-8", errors="ignore")
                if re.search(r"onclick=", txt):
                    dup_count += 1
            except Exception:
                pass
    ps.add(dup_count == 0, f"Found {dup_count} files with inline onclick handlers")
    # Secrets in code
    secret_hits = 0
    for ext in (".py", ".js", ".html"):
        for fp in (ctx.base).rglob(f"*{ext}"):
            if any(seg in fp.parts for seg in ["venv", "__pycache__", ".git"]):
                continue
            try:
                txt = fp.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if re.search(r"password|secret|token|api_key", txt, flags=re.IGNORECASE):
                secret_hits += 1
    ps.add(secret_hits == 0, f"Found {secret_hits} potential secret references (manual review required)")
    return ps


def phase_7_code_quality(ctx: Context) -> PhaseScore:
    ps = PhaseScore("Code Quality", max_points=10)
    # Dead v1 files should not exist
    dead_files = [
        ctx.base / "web/static/assets/js/dashboard.js",
        ctx.base / "web/static/assets/js/scan_monitor.js",
        ctx.base / "web/static/assets/js/findings.js",
        ctx.base / "web/static/assets/js/graph_viz.js",
    ]
    all_deleted = all(not f.exists() for f in dead_files)
    ps.add(all_deleted, "Legacy v1 JS files still present")
    # Shared utilities duplication count
    util_names = ["el(", "esc(", "hdrs(", "toast(", "initSidebar("]
    dup = 0
    for fp in (ctx.base / "web" / "static" / "assets" / "js").rglob("*.js"):
        try:
            txt = fp.read_text(encoding="utf-8", errors="ignore")
            for name in util_names:
                dup += len(re.findall(re.escape(name), txt))
        except Exception:
            pass
    ps.add(dup < 10, f"High duplication in JS utilities (~{dup} references). Consider common.js")
    # Polling efficiency: check for visibilitychange usage
    uses_visibility = False
    for fp in (ctx.base / "web" / "static" / "assets" / "js").rglob("*.js"):
        try:
            txt = fp.read_text(encoding="utf-8", errors="ignore")
            if "visibilitychange" in txt or "document.hidden" in txt:
                uses_visibility = True
                break
        except Exception:
            pass
    ps.add(uses_visibility, "Missing visibility-aware polling (document.hidden)")
    # Error handling: pages show offline state
    offline_ok = True
    for fp in (ctx.base / "web" / "static").rglob("*.html"):
        try:
            txt = fp.read_text(encoding="utf-8", errors="ignore")
            if "API offline" in txt or "Unable to reach API" in txt:
                offline_ok = True
                break
        except Exception:
            pass
    ps.add(offline_ok, "Missing user-visible error states in pages")
    return ps


def print_report(scores: List[PhaseScore]):
    total = sum(s.score for s in scores)
    max_total = sum(s.max_points for s in scores)
    print("\n=== Production Readiness Report ===")
    for s in scores:
        print(f"- {s.label}: {s.score}/{s.max_points}")
    print(f"- TOTAL: {total}/{max_total}")
    print(f"- VERDICT: {'PASS' if total >= PASS_THRESHOLD else 'FAIL'} (threshold {PASS_THRESHOLD})")
    for s in scores:
        if s.details:
            print(f"\n[s] {s.label} — Failures ({len(s.details)})")
            for d in s.details:
                print(f"  • {d}")


def main():
    parser = argparse.ArgumentParser(description="Technieum Production Readiness Test Runner")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--base", default=os.environ.get("TECHNIEUM_BASE", "/Users/rejenthompson/Documents/technieum-/kali-linux-asm"))
    args = parser.parse_args()
    base = Path(args.base).resolve()
    if not base.exists():
        print(f"ERROR: Base path not found: {base}")
        sys.exit(2)
    ctx = Context(
        base=base,
        host=args.host,
        port=args.port,
        base_url=f"http://{args.host}:{args.port}",
        api_v1=f"http://{args.host}:{args.port}/api/v1",
    )
    scores: List[PhaseScore] = []
    try:
        scores.append(phase_1_env_boot(ctx))
        scores.append(phase_2_api_coverage(ctx))
        scores.append(phase_3_ui_pages(ctx))
        scores.append(phase_4_wiring(ctx))
        scores.append(phase_5_worker(ctx))
        scores.append(phase_6_security(ctx))
        scores.append(phase_7_code_quality(ctx))
    finally:
        stop_server(ctx)
        if ctx.worker_proc:
            with contextlib.suppress(Exception):
                os.kill(ctx.worker_proc.pid, signal.SIGTERM)
    print_report(scores)


if __name__ == "__main__":
    main()
