"""Universal Output File Ingestion Engine for Technieum Assessment Dashboard.

Recursively scans any scan output directory, auto-detects and parses all
supported file types (JSON/JSONL, TXT, CSV, XML, LOG), routes each file to
one of 19 logical UI modules, and returns structured data for the API layer.

Zero manual configuration — works with any tool set.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
OUTPUT_DIR = Path(
    os.environ.get(
        "TECHNIEUM_OUTPUT_DIR",
        str(Path(__file__).resolve().parents[3] / "output"),
    )
)

# Maximum bytes read from a single file before truncation (25 MB)
_MAX_READ_BYTES = 25 * 1024 * 1024

# Maximum lines returned for large TXT/LOG files in list endpoints
_MAX_LINES = 10000

# Supported extensions for recursive scan
SUPPORTED_EXTENSIONS = frozenset({".json", ".txt", ".csv", ".xml", ".log", ".err"})

# ---------------------------------------------------------------------------
# Module routing table
# ---------------------------------------------------------------------------
# Each key is a module name; value is list of case-insensitive regex patterns
# matched against the *filename only* (not full path).
MODULE_PATTERNS: Dict[str, List[str]] = {
    # ─── Discovery ────────────────────────────────────────────────────────
    "subdomains": [
        r"^(?:all_|passive_|active_|resolved_)?subdomains(?:_raw)?\.txt$",
        r"^subfinder\.txt$",
        r"^assetfinder\.txt$",
        r"^crtsh\.txt$",
        r"^phase1_summary\.json$",
        r"^amass\.txt$",
        r"^findomain\.txt$",
    ],
    "dns": [
        r"^dnsx_resolved\.json$",
        r"^dns.*\.json$",
        r"^resolved.*\.(?:txt|json)$",
    ],
    "alive_hosts": [
        r"^alive(?:_hosts|_urls)?(?:_raw)?\.txt$",
        r"^active_subdomains(?:_raw)?\.txt$",
        r"^httpx_alive\.json$",
        r"^.*alive.*\.(?:json|txt)$",
    ],
    "asn_ip": [
        r"^asn_(?:by_ip|info|summary|cidrs(?:_filtered)?|ips)\.txt$",
        r"^asn.*\.(?:txt|json)$",
        r"^all_ips\.txt$",
        r"^resolved_ips\.txt$",
        r"^.*_cidrs.*\.txt$",
    ],
    "domain_intelligence": [
        r"^whois\.txt$",
        r"^prescan_risk_profile\.json$",
    ],
    "cloud_exposure": [
        r"^cloud_assets(?:_raw)?\.txt$",
        r"^cloud_enum\.txt$",
        r"^s3scanner\.txt$",
        r"^goblob(?:_accounts)?\.txt$",
        r"^gcpbucketbrute\.txt$",
        r"^keywords\.txt$",
    ],
    "cert_transparency": [
        r"^certspotter\.txt$",
        r"^ct_.*\.(?:txt|json)$",
        r"^certificate.*\.(?:txt|json)$",
        r"^crt.*\.(?:txt|json)$",
    ],
    # ─── Content Discovery ────────────────────────────────────────────────
    "directory_bruteforce": [
        r"^ffuf_.*\.json$",
        r"^feroxbuster_.*\.txt$",
        r"^dirsearch_.*\.txt$",
        r"^all_discovered_paths\.txt$",
        r"^brute_targets\.txt$",
    ],
    "url_collection": [
        r"^gau\.txt$",
        r"^waybackurls\.txt$",
        r"^katana\.txt$",
        r"^gospider(?:_raw|_targets)?\.txt$",
        r"^hakrawler\.txt$",
        r"^spideyx.*\.txt$",
        r"^cariddi_(?:endpoints|results)\.(?:txt|json)$",
        r"^all_urls(?:_raw)?\.txt$",
        r"^param_urls\.txt$",
    ],
    "javascript": [
        r"^javascript_files\.txt$",
        r"^mantra_secrets\.txt$",
        r"^.*js.*\.(?:txt|json)$",
    ],
    "api_discovery": [
        r"^arjun_.*\.(?:json|txt)$",
    ],
    "secrets_leaks": [
        r"^gitleaks_report\.json$",
        r"^trufflehog_report\.json$",
        r"^git_secrets\.txt$",
        r"^cariddi_secrets(?:_only)?\.txt$",
        r"^.*(?:secret|leak).*\.(?:txt|json)$",
    ],
    # ─── Vulnerability ─────────────────────────────────────────────────────
    "port_scanning": [
        r"^nmap(?:_all)?\.xml$",
        r"^nmap_all\.txt$",
        r"^ports.*\.(?:json|txt)$",
    ],
    "vulnerability_scanning": [
        r"^nikto_.*\.json$",
        r"^wapiti_.*\.json$",
        r"^sqlmap_results\.txt$",
        r"^wpscan_.*\.json$",
        r"^retirejs_results\.json$",
        r"^cve_(?:matches|summary)\.json$",
        r"^vulnerabilities_summary\.json$",
        r"^epss_scores\.json$",
        r"^(?:retirejs|retire)_.*\.json$",
    ],
    "ssl_tls": [
        r"^sslyze_.*\.json$",
        r"^testssl.*\.(?:json|log)$",
        r"^tls_compliance\.json$",
    ],
    # ─── Intel / Compliance ────────────────────────────────────────────────
    "threat_intel": [
        r"^blocklists\.csv$",
        r"^threatminer\.json$",
        r"^urlhaus.*\.json$",
        r"^threatfox\.json$",
        r"^psbdmp\.json$",
        r"^phase5_threat_intel_summary\.json$",
        r"^threat_intel_summary\.json$",
    ],
    "compliance": [
        r"^compliance_summary\.json$",
        r"^aggregated_findings\.json$",
        r"^(?:gdpr|hipaa|pci_dss|nist_csf|soc2)\.log$",
        r"^testssl\.log$",
        r"^tls_compliance\.json$",
        r"^mapping\.json$",
    ],
    "change_detection": [
        r"^change_(?:alerts|delta|detection_summary)\.json$",
        r"^(?:baseline|snapshot).*\.(?:json|log)$",
        r"^current_snapshot\.json$",
        r"^alerts\.log$",
    ],
    "attack_graph": [
        r"^attack_graph(?:_summary)?\.json$",
        r"^attack_paths\.json$",
        r"^all_assets\.json$",
        r"^risk_summary\.json$",
    ],
    "tool_errors": [
        r"\.err$",
    ],
}


# ---------------------------------------------------------------------------
# Compiled pattern cache
# ---------------------------------------------------------------------------
_COMPILED: Dict[str, List[re.Pattern]] = {
    mod: [re.compile(p, re.IGNORECASE) for p in pats]
    for mod, pats in MODULE_PATTERNS.items()
}

# Module priority order (first match wins)
_MODULE_ORDER = list(MODULE_PATTERNS.keys())


# ---------------------------------------------------------------------------
# File router
# ---------------------------------------------------------------------------
def route_file(filename: str) -> Optional[str]:
    """Return the module name for *filename*, or None if unrecognised."""
    fn = filename.lower()
    for mod in _MODULE_ORDER:
        for pat in _COMPILED[mod]:
            if pat.search(fn):
                return mod
    return None


# ---------------------------------------------------------------------------
# File parser
# ---------------------------------------------------------------------------

def _read_safe(path: Path) -> str:
    """Read up to _MAX_READ_BYTES from path; return UTF-8 text."""
    size = path.stat().st_size
    with path.open("rb") as fh:
        raw = fh.read(min(size, _MAX_READ_BYTES))
    return raw.decode("utf-8", errors="replace")


def _parse_json(content: str) -> Any:
    """Parse JSON or JSONL; returns list for JSONL multi-object files."""
    stripped = content.strip()
    # Try plain JSON first
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass
    # Try JSONL (one object per line)
    objects: List[Any] = []
    for line in stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            objects.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    if objects:
        return objects
    return {"raw": stripped[:2000], "parse_error": True}


def _parse_txt(content: str) -> Dict[str, Any]:
    lines = [ln.rstrip("\r\n") for ln in content.splitlines() if ln.strip()]
    return {
        "type": "txt",
        "lines": lines[:_MAX_LINES],
        "total_lines": len(lines),
        "truncated": len(lines) > _MAX_LINES,
    }


def _files_meta(paths: List[Path], scan_dir: Path) -> List[Dict[str, Any]]:
    """Compact file metadata list used by UI for logging visibility."""
    out: List[Dict[str, Any]] = []
    for p in paths:
        try:
            out.append({
                "file": str(p.relative_to(scan_dir)),
                "size_bytes": p.stat().st_size,
            })
        except Exception:
            out.append({"file": p.name, "size_bytes": None})
    return out


def _parse_csv(content: str) -> Dict[str, Any]:
    try:
        reader = csv.DictReader(io.StringIO(content))
        rows = [row for row in reader]
        return {
            "type": "csv",
            "columns": list(reader.fieldnames or []),
            "rows": rows[:_MAX_LINES],
            "total_rows": len(rows),
            "truncated": len(rows) > _MAX_LINES,
        }
    except Exception:
        return _parse_txt(content)


def _parse_xml_nmap(root: ET.Element) -> Dict[str, Any]:
    """Parse nmap XML into a list of host records."""
    hosts: List[Dict[str, Any]] = []
    for host in root.findall("host"):
        status_el = host.find("status")
        state = status_el.get("state", "unknown") if status_el is not None else "unknown"
        addrs = {
            a.get("addrtype", "addr"): a.get("addr", "")
            for a in host.findall("address")
        }
        ports: List[Dict[str, Any]] = []
        for port in host.findall(".//port"):
            state_el = port.find("state")
            svc_el = port.find("service")
            ports.append({
                "portid": port.get("portid"),
                "protocol": port.get("protocol"),
                "state": state_el.get("state") if state_el is not None else None,
                "service": svc_el.get("name") if svc_el is not None else None,
                "product": svc_el.get("product") if svc_el is not None else None,
                "version": svc_el.get("version") if svc_el is not None else None,
            })
        hostname_el = host.find(".//hostname")
        hosts.append({
            "ip": addrs.get("ipv4") or addrs.get("ipv6") or "",
            "hostname": hostname_el.get("name") if hostname_el is not None else "",
            "state": state,
            "ports": ports,
        })
    return {"type": "nmap_xml", "hosts": hosts, "host_count": len(hosts)}


def _parse_xml(content: str) -> Dict[str, Any]:
    """Generic XML → dict parser (nmap-aware)."""
    try:
        root = ET.fromstring(content)  # nosec B314
        if root.tag == "nmaprun":
            return _parse_xml_nmap(root)
        # Generic fallback: return as nested dict
        def _el_to_dict(el: ET.Element) -> Dict[str, Any]:
            d: Dict[str, Any] = dict(el.attrib)
            children = list(el)
            if children:
                child_list = [_el_to_dict(c) for c in children[:500]]
                d["_children"] = child_list
            elif el.text and el.text.strip():
                d["_text"] = el.text.strip()
            return d
        return {"type": "xml", "tag": root.tag, "data": _el_to_dict(root)}
    except ET.ParseError as exc:
        return {"type": "xml", "parse_error": str(exc), "raw": content[:2000]}


def parse_file(path: Path) -> Dict[str, Any]:
    """Parse any supported file; return metadata + parsed data."""
    ext = path.suffix.lower()
    meta: Dict[str, Any] = {
        "filename": path.name,
        "ext": ext.lstrip("."),
        "size_bytes": path.stat().st_size,
        "status": "ok",
    }
    try:
        content = _read_safe(path)
    except Exception as exc:
        meta["status"] = "read_error"
        meta["error"] = str(exc)
        return meta

    try:
        if ext == ".json":
            meta["data"] = _parse_json(content)
        elif ext == ".csv":
            meta["data"] = _parse_csv(content)
        elif ext == ".xml":
            meta["data"] = _parse_xml(content)
        else:  # .txt .log .err
            meta["data"] = _parse_txt(content)
    except Exception as exc:
        meta["status"] = "parse_error"
        meta["error"] = str(exc)
        meta["data"] = {"raw": content[:2000]}

    return meta


# ---------------------------------------------------------------------------
# Scan directory locator
# ---------------------------------------------------------------------------

def find_scan_dir(domain: str, scan_id: int) -> Optional[Path]:
    """Locate the output directory for a given domain and scan ID."""
    base = re.sub(r"[.\-]", "_", domain)
    candidates = [
        OUTPUT_DIR / f"{base}_scan_{scan_id}",
        OUTPUT_DIR / f"{base}_{scan_id}",
    ]
    for c in candidates:
        if c.is_dir():
            return c
    # Glob fallback — pick first dir whose name contains base and the scan_id
    for d in sorted(OUTPUT_DIR.iterdir()):
        if d.is_dir() and str(scan_id) in d.name and base in d.name:
            return d
    return None


# ---------------------------------------------------------------------------
# Recursive file collector
# ---------------------------------------------------------------------------

def collect_files(scan_dir: Path) -> List[Path]:
    """Return all supported files under scan_dir, sorted."""
    skip_dirs = {"skipfish"}
    result: List[Path] = []
    for f in scan_dir.rglob("*"):
        if not f.is_file():
            continue
        # Skip skipfish internal tree
        if any(part in skip_dirs for part in f.relative_to(scan_dir).parts[:-1]):
            continue
        if f.suffix.lower() in SUPPORTED_EXTENSIONS:
            result.append(f)
    return sorted(result)


# ---------------------------------------------------------------------------
# Main ingestion entry-point
# ---------------------------------------------------------------------------

def ingest_scan(domain: str, scan_id: int) -> Optional[Dict[str, Any]]:
    """Ingest all output files for a scan.

    Returns a dict keyed by module name, each containing a list of parsed
    file records, or None if the scan directory was not found.
    """
    scan_dir = find_scan_dir(domain, scan_id)
    if not scan_dir:
        return None

    files = collect_files(scan_dir)
    modules: Dict[str, List[Dict[str, Any]]] = {}
    unrouted: List[str] = []

    for f in files:
        mod = route_file(f.name)
        if mod:
            parsed = parse_file(f)
            parsed["relative_path"] = str(f.relative_to(scan_dir))
            modules.setdefault(mod, []).append(parsed)
        else:
            unrouted.append(str(f.relative_to(scan_dir)))

    return {
        "scan_dir": str(scan_dir),
        "domain": domain,
        "scan_id": scan_id,
        "file_count": len(files),
        "module_count": len(modules),
        "modules": modules,
        "unrouted": unrouted,
    }


# ---------------------------------------------------------------------------
# Per-module data extractors (used by API endpoints)
# ---------------------------------------------------------------------------

def _text_lines(parsed_files: List[Dict[str, Any]]) -> List[str]:
    """Flatten all text lines from a list of parsed TXT/LOG files."""
    lines: List[str] = []
    for f in parsed_files:
        d = f.get("data", {})
        if isinstance(d, dict) and "lines" in d:
            lines.extend(d["lines"])
        elif isinstance(d, list):
            for item in d:
                if isinstance(item, str):
                    lines.append(item)
                elif isinstance(item, dict):
                    lines.append(str(item.get("host") or item.get("url") or item.get("subdomain") or ""))
    # Deduplicate preserving order, skip empty
    seen: set = set()
    out: List[str] = []
    for ln in lines:
        ln = ln.strip()
        if ln and ln not in seen:
            seen.add(ln)
            out.append(ln)
    return out


def _json_records(parsed_files: List[Dict[str, Any]], key: Optional[str] = None) -> List[Any]:
    """Flatten parsed JSON records from module files."""
    records: List[Any] = []
    for f in parsed_files:
        d = f.get("data")
        if d is None:
            continue
        if isinstance(d, list):
            if key:
                for item in d:
                    if isinstance(item, dict) and key in item:
                        records.append(item)
            else:
                records.extend(d)
        elif isinstance(d, dict):
            if key and key in d:
                val = d[key]
                if isinstance(val, list):
                    records.extend(val)
                else:
                    records.append(val)
            else:
                records.append(d)
    return records


def extract_subdomains(scan_dir: Path) -> Dict[str, Any]:
    seen: set = set()
    subs: List[str] = []
    for fn in ["all_subdomains.txt", "passive_subdomains.txt", "active_subdomains.txt",
               "subdomains.txt", "subfinder.txt", "assetfinder.txt", "crtsh.txt",
               "amass.txt", "findomain.txt"]:
        for f in [scan_dir / fn, scan_dir / "phase1_discovery" / fn,
                  scan_dir / "phase1_discovery" / "temp_subdomains" / fn,
                  scan_dir / "phase1_discovery" / "subdomains" / fn]:
            if f.is_file():
                for ln in _parse_txt(_read_safe(f))["lines"]:
                    ln = ln.strip()
                    if ln and ln not in seen:
                        seen.add(ln)
                        subs.append(ln)
    return {
        "subdomains": subs[:_MAX_LINES],
        "total": len(subs),
        "truncated": len(subs) > _MAX_LINES,
    }


def extract_dns(scan_dir: Path) -> Dict[str, Any]:
    records: List[Dict[str, Any]] = []
    seen_hosts: set = set()
    for f in [scan_dir / "dnsx_resolved.json",
              scan_dir / "phase1_discovery" / "dnsx_resolved.json"]:
        if f.is_file():
            parsed = _parse_json(_read_safe(f))
            items = parsed if isinstance(parsed, list) else [parsed]
            for item in items:
                if not isinstance(item, dict):
                    continue
                host = item.get("host") or ""
                if host in seen_hosts:
                    continue
                seen_hosts.add(host)
                records.append({
                    "host": host,
                    "ips": item.get("a") or [],
                    "cnames": item.get("cname") or [],
                    "status": item.get("status_code") or item.get("status") or "",
                    "ttl": item.get("ttl") or "",
                })
    return {"records": records[:_MAX_LINES], "total": len(records)}


def extract_asn(scan_dir: Path) -> Dict[str, Any]:
    ips: List[str] = []
    cidrs: List[str] = []
    info_lines: List[str] = []
    for phase in ["", "phase1_discovery/asn", "phase2_intel/osint"]:
        base = (scan_dir / phase) if phase else scan_dir
        if not base.is_dir():
            continue
        for fn in ["asn_ips.txt", "all_ips.txt", "resolved_ips.txt"]:
            f = base / fn
            if f.is_file():
                ips.extend(ln for ln in _parse_txt(_read_safe(f))["lines"] if ln.strip())
        for fn in ["asn_cidrs.txt", "asn_cidrs_filtered.txt"]:
            f = base / fn
            if f.is_file():
                cidrs.extend(ln for ln in _parse_txt(_read_safe(f))["lines"] if ln.strip())
        for fn in ["asn_info.txt", "asn_summary.txt", "asn_by_ip.txt"]:
            f = base / fn
            if f.is_file():
                info_lines.extend(ln for ln in _parse_txt(_read_safe(f))["lines"] if ln.strip())
    # Deduplicate
    ips = list(dict.fromkeys(ips))
    cidrs = list(dict.fromkeys(cidrs))
    return {
        "ips": ips[:500],
        "cidrs": cidrs[:200],
        "ip_count": len(ips),
        "cidr_count": len(cidrs),
        "info": info_lines[:100],
    }


def extract_alive_hosts(scan_dir: Path) -> Dict[str, Any]:
    hosts: List[Any] = []
    seen: set = set()
    # httpx JSON
    for phase in ["", "phase1_discovery"]:
        f = (scan_dir / phase / "httpx_alive.json") if phase else (scan_dir / "httpx_alive.json")
        if f.is_file():
            parsed = _parse_json(_read_safe(f))
            items = parsed if isinstance(parsed, list) else [parsed]
            for item in items:
                if isinstance(item, dict):
                    key = item.get("url") or item.get("host") or item.get("input") or ""
                    if key and key not in seen:
                        seen.add(key)
                        hosts.append(item)
    # TXT fallback
    if not hosts:
        for fn in ["alive_urls.txt", "alive_hosts.txt"]:
            for phase in ["", "phase1_discovery"]:
                f = (scan_dir / phase / fn) if phase else (scan_dir / fn)
                if f.is_file():
                    for ln in _parse_txt(_read_safe(f))["lines"]:
                        ln = ln.strip()
                        if ln and ln not in seen:
                            seen.add(ln)
                            hosts.append({"url": ln})
    return {"hosts": hosts[:1000], "total": len(hosts)}


def extract_directories(scan_dir: Path) -> Dict[str, Any]:
    results: Dict[str, List[Any]] = {}
    # feroxbuster TXT files - first N lines only
    for f in sorted(scan_dir.rglob("feroxbuster_*.txt")):
        if "all" in f.name:
            continue  # skip aggregate
        lines = _parse_txt(_read_safe(f))["lines"]
        urls = [ln for ln in lines if ln.startswith("http") or re.match(r"\d{3}", ln)]
        if urls:
            results[f.name] = urls[:200]
    # ffuf JSON
    for f in sorted(scan_dir.rglob("ffuf_*.json")):
        if "all" in f.name:
            continue
        parsed = _parse_json(_read_safe(f))
        if isinstance(parsed, dict) and "results" in parsed:
            results[f.name] = (parsed["results"] or [])[:200]
    # dirsearch TXT
    for f in sorted(scan_dir.rglob("dirsearch_*.txt")):
        if "all" in f.name:
            continue
        lines = _parse_txt(_read_safe(f))["lines"]
        urls = [ln for ln in lines if "/" in ln and ln.strip()]
        if urls:
            results[f.name] = urls[:200]

    total = sum(len(v) for v in results.values())
    return {"tools": results, "file_count": len(results), "total_findings": total}


def extract_urls(scan_dir: Path) -> Dict[str, Any]:
    sources: Dict[str, int] = {}
    sample: List[str] = []
    seen: set = set()
    tool_files = {
        "gau": "gau.txt",
        "waybackurls": "waybackurls.txt",
        "katana": "katana.txt",
        "gospider": "gospider.txt",
        "hakrawler": "hakrawler.txt",
    }
    p3 = scan_dir / "phase3_content" / "urls"
    for tool, fn in tool_files.items():
        for base in [scan_dir, p3]:
            f = base / fn
            if f.is_file():
                lines = _parse_txt(_read_safe(f))["lines"]
                count = len(set(lines))
                sources[tool] = count
                for ln in lines[:100]:
                    if ln not in seen:
                        seen.add(ln)
                        sample.append(ln)
                break
    return {
        "sources": sources,
        "total": sum(sources.values()),
        "sample": sample[:500],
    }


def extract_secrets(scan_dir: Path) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    for f in scan_dir.rglob("gitleaks_report.json"):
        parsed = _parse_json(_read_safe(f))
        items = parsed if isinstance(parsed, list) else [parsed]
        for item in items:
            if isinstance(item, dict) and item:
                findings.append({**item, "_source": "gitleaks"})
    for f in scan_dir.rglob("trufflehog_report.json"):
        parsed = _parse_json(_read_safe(f))
        items = parsed if isinstance(parsed, list) else [parsed]
        for item in items:
            if isinstance(item, dict) and item:
                findings.append({**item, "_source": "trufflehog"})
    for fn in ["cariddi_secrets.txt", "cariddi_secrets_only.txt", "git_secrets.txt"]:
        for f in scan_dir.rglob(fn):
            lines = _parse_txt(_read_safe(f))["lines"]
            for ln in lines:
                findings.append({"line": ln, "_source": fn})
    return {"findings": findings[:500], "total": len(findings), "has_secrets": len(findings) > 0}


def extract_ports(scan_dir: Path) -> Dict[str, Any]:
    hosts: List[Dict[str, Any]] = []
    xml_files = list(scan_dir.rglob("nmap_all.xml")) + list(scan_dir.rglob("nmap.xml"))
    txt_files = list(scan_dir.rglob("nmap_all.txt")) + list(scan_dir.rglob("nmap.txt"))
    parse_errors: List[str] = []
    for f in xml_files:
        parsed = _parse_xml(_read_safe(f))
        if parsed.get("type") == "nmap_xml":
            hosts.extend(parsed.get("hosts", []))
        elif parsed.get("parse_error"):
            parse_errors.append(f"{f.name}: {parsed.get('parse_error')}")
    # de-dupe hosts by ip+hostname, merge ports
    dedup: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for h in hosts:
        key = (h.get("ip", ""), h.get("hostname", ""))
        if key not in dedup:
            dedup[key] = {"ip": key[0], "hostname": key[1], "state": h.get("state"), "ports": []}
        dedup[key]["ports"].extend(h.get("ports", []))
    hosts = list(dedup.values())
    # TXT fallback - parse open ports from text output
    if not hosts:
        all_lines: List[str] = []
        for f in txt_files:
            lines = _parse_txt(_read_safe(f))["lines"]
            if lines:
                all_lines.extend(lines)
        if all_lines:
            return {
                "raw_lines": all_lines[:5000],
                "total_lines": len(all_lines),
                "hosts": [],
                "files": _files_meta(txt_files, scan_dir),
            }
    open_ports = sum(
        len([p for p in h.get("ports", []) if p.get("state") == "open"])
        for h in hosts
    )
    return {
        "hosts": hosts[:1000],
        "host_count": len(hosts),
        "open_ports": open_ports,
        "files": _files_meta(xml_files + txt_files, scan_dir),
        "parse_errors": parse_errors[:50],
    }


def extract_vulnerabilities(scan_dir: Path) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    # nikto
    for f in scan_dir.rglob("nikto_*.json"):
        if "all" in f.name or "targets" in f.name:
            continue
        parsed = _parse_json(_read_safe(f))
        items = parsed if isinstance(parsed, list) else [parsed]
        for item in items:
            if isinstance(item, dict):
                vulns = item.get("vulnerabilities") or item.get("findings") or item.get("result") or []
                if isinstance(vulns, list):
                    for v in vulns:
                        if isinstance(v, dict):
                            findings.append({**v, "_tool": "nikto", "_target": f.stem})
                elif isinstance(item, dict) and item.get("id"):
                    findings.append({**item, "_tool": "nikto"})
    # sqlmap results
    for f in scan_dir.rglob("sqlmap_results.txt"):
        lines = _parse_txt(_read_safe(f))["lines"]
        vuln_lines = [ln for ln in lines if "VULNERABLE" in ln.upper() or "INJECTION" in ln.upper()]
        for ln in vuln_lines:
            findings.append({"line": ln, "_tool": "sqlmap"})
    # CVE matches
    for f in [scan_dir / "cve_matches.json", scan_dir / "phase6_cve_correlation" / "cve_matches.json"]:
        if f.is_file():
            parsed = _parse_json(_read_safe(f))
            items = parsed if isinstance(parsed, list) else ([parsed] if isinstance(parsed, dict) else [])
            for item in items:
                if isinstance(item, dict) and item:
                    findings.append({**item, "_tool": "cve_correlation"})
    return {"findings": findings[:500], "total": len(findings)}


def extract_ssl(scan_dir: Path) -> Dict[str, Any]:
    results: List[Dict[str, Any]] = []
    for f in scan_dir.rglob("sslyze_*.json"):
        if "all" in f.name or "targets" in f.name:
            continue
        parsed = _parse_json(_read_safe(f))
        if isinstance(parsed, dict):
            results.append({"target": f.stem.replace("sslyze_", ""), "data": parsed})
    return {"results": results[:50], "total": len(results)}


def extract_threat_intel(scan_dir: Path) -> Dict[str, Any]:
    summary: Dict[str, Any] = {}
    # phase5 summary
    for fn in ["phase5_threat_intel_summary.json", "threat_intel_summary.json"]:
        for base in [scan_dir, scan_dir / "phase5_threat_intel"]:
            f = base / fn
            if f.is_file():
                parsed = _parse_json(_read_safe(f))
                if isinstance(parsed, dict):
                    summary.update(parsed)
    blocklist_hits: List[Any] = []
    for f in scan_dir.rglob("blocklists.csv"):
        rows = _parse_csv(_read_safe(f))
        if isinstance(rows, dict) and "rows" in rows:
            blocklist_hits.extend(rows["rows"])
    return {"summary": summary, "blocklist_hits": blocklist_hits[:200], "total_hits": len(blocklist_hits)}


def extract_compliance(scan_dir: Path) -> Dict[str, Any]:
    summary: Dict[str, Any] = {}
    frameworks: Dict[str, List[str]] = {}
    for f in [scan_dir / "compliance_summary.json",
              scan_dir / "phase8_compliance" / "compliance_summary.json"]:
        if f.is_file():
            parsed = _parse_json(_read_safe(f))
            if isinstance(parsed, dict):
                summary.update(parsed)
    for fw in ["gdpr", "hipaa", "pci_dss", "nist_csf", "soc2"]:
        for f in scan_dir.rglob(f"{fw}.log"):
            lines = _parse_txt(_read_safe(f))["lines"]
            frameworks[fw] = lines[:100]
    return {"summary": summary, "frameworks": frameworks}


def extract_attack_graph(scan_dir: Path) -> Dict[str, Any]:
    graph: Dict[str, Any] = {}
    for fn in ["attack_graph.json", "phase9_attack_graph/attack_graph.json"]:
        f = scan_dir / fn
        if f.is_file():
            parsed = _parse_json(_read_safe(f))
            if isinstance(parsed, dict):
                graph = parsed
            break
    paths: List[Any] = []
    for fn in ["attack_paths.json", "phase9_attack_graph/attack_paths.json"]:
        f = scan_dir / fn
        if f.is_file():
            parsed = _parse_json(_read_safe(f))
            paths = parsed if isinstance(parsed, list) else (parsed.get("paths", []) if isinstance(parsed, dict) else [])
            break
    risk: Dict[str, Any] = {}
    for f in [scan_dir / "risk_summary.json", scan_dir / "phase6_cve_correlation" / "risk_summary.json"]:
        if f.is_file():
            parsed = _parse_json(_read_safe(f))
            if isinstance(parsed, dict):
                risk = parsed
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    return {
        "nodes": nodes[:500],
        "edges": edges[:1000],
        "paths": paths[:50],
        "risk": risk,
        "node_count": len(nodes),
        "edge_count": len(edges),
    }


def extract_change_detection(scan_dir: Path) -> Dict[str, Any]:
    summary: Dict[str, Any] = {}
    alerts: List[Any] = []
    delta: Dict[str, Any] = {}
    for fn in ["change_detection_summary.json"]:
        for base in [scan_dir, scan_dir / "phase7_change_detection"]:
            f = base / fn
            if f.is_file():
                parsed = _parse_json(_read_safe(f))
                if isinstance(parsed, dict):
                    summary.update(parsed)
    for fn in ["change_alerts.json"]:
        for base in [scan_dir, scan_dir / "phase7_change_detection"]:
            f = base / fn
            if f.is_file():
                parsed = _parse_json(_read_safe(f))
                alerts = parsed if isinstance(parsed, list) else (parsed.get("alerts", []) if isinstance(parsed, dict) else [])
    for fn in ["change_delta.json"]:
        for base in [scan_dir, scan_dir / "phase7_change_detection"]:
            f = base / fn
            if f.is_file():
                parsed = _parse_json(_read_safe(f))
                if isinstance(parsed, dict):
                    delta = parsed
    return {"summary": summary, "alerts": alerts[:200], "delta": delta}


def extract_cloud(scan_dir: Path) -> Dict[str, Any]:
    assets: List[str] = []
    seen: set = set()
    for fn in ["cloud_assets.txt", "cloud_enum.txt", "goblob.txt",
               "s3scanner.txt", "gcpbucketbrute.txt"]:
        for base in [scan_dir, scan_dir / "phase1_discovery" / "cloud"]:
            f = base / fn
            if f.is_file():
                for ln in _parse_txt(_read_safe(f))["lines"]:
                    ln = ln.strip()
                    if ln and ln not in seen:
                        seen.add(ln)
                        assets.append(ln)

    aws = [a for a in assets if "s3" in a.lower() or "amazonaws" in a.lower() or "aws" in a.lower()]
    gcp = [a for a in assets if "storage.googleapis" in a.lower() or "gcp" in a.lower() or "gcs" in a.lower()]
    azure = [a for a in assets if "blob.core.windows" in a.lower() or "azure" in a.lower()]
    other = [a for a in assets if a not in aws and a not in gcp and a not in azure]
    return {
        "total": len(assets),
        "assets": assets[:300],
        "aws": aws[:100],
        "gcp": gcp[:100],
        "azure": azure[:100],
        "other": other[:100],
    }


def extract_cert_transparency(scan_dir: Path) -> Dict[str, Any]:
    certs: List[str] = []
    seen: set = set()
    for fn in ["certspotter.txt", "crtsh.txt"]:
        for base in [scan_dir, scan_dir / "phase1_discovery" / "ct",
                     scan_dir / "phase1_discovery" / "temp_subdomains"]:
            f = base / fn
            if f.is_file():
                for ln in _parse_txt(_read_safe(f))["lines"]:
                    ln = ln.strip()
                    if ln and ln not in seen:
                        seen.add(ln)
                        certs.append(ln)
    return {"domains": certs[:1000], "total": len(certs)}


def extract_javascript(scan_dir: Path) -> Dict[str, Any]:
    js_files: List[str] = []
    for f in [scan_dir / "javascript_files.txt",
              scan_dir / "phase3_content" / "urls" / "javascript_files.txt"]:
        if f.is_file():
            js_files = _parse_txt(_read_safe(f))["lines"]
    secrets: List[str] = []
    for fn in ["mantra_secrets.txt"]:
        for base in [scan_dir, scan_dir / "phase3_content"]:
            f = base / fn
            if f.is_file():
                secrets = _parse_txt(_read_safe(f))["lines"]
    return {
        "js_files": js_files[:500],
        "total_js": len(js_files),
        "secrets": secrets[:200],
        "total_secrets": len(secrets),
    }


def extract_api_discovery(scan_dir: Path) -> Dict[str, Any]:
    endpoints: List[Any] = []
    for f in scan_dir.rglob("arjun_all.json"):
        parsed = _parse_json(_read_safe(f))
        if isinstance(parsed, list):
            endpoints.extend(parsed)
        elif isinstance(parsed, dict):
            for k, v in parsed.items():
                if isinstance(v, list):
                    for ep in v:
                        endpoints.append({"url": k, "params": ep})
    return {"endpoints": endpoints[:500], "total": len(endpoints)}


def extract_whois(scan_dir: Path) -> Dict[str, Any]:
    raw: str = ""
    risk: Dict[str, Any] = {}
    for base in [scan_dir, scan_dir / "phase0_prescan", scan_dir / "phase1_discovery"]:
        f = base / "whois.txt"
        if f.is_file():
            raw = _read_safe(f)[:5000]
            break
    for base in [scan_dir, scan_dir / "phase0_prescan"]:
        f = base / "prescan_risk_profile.json"
        if f.is_file():
            parsed = _parse_json(_read_safe(f))
            if isinstance(parsed, dict):
                risk = parsed
            break
    # Parse WHOIS key fields
    kv: Dict[str, str] = {}
    if raw:
        for line in raw.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                k = k.strip()
                v = v.strip()
                if k and v and k.lower() not in ("http", "https"):
                    kv[k] = v
    return {"raw": raw, "fields": kv, "risk_profile": risk}


def extract_tool_errors(scan_dir: Path) -> Dict[str, Any]:
    """Extract tool error and timeout messages from .err files."""
    errors: List[Dict[str, Any]] = []
    for f in scan_dir.rglob("*.err"):
        if not f.is_file():
            continue
        content = _read_safe(f)
        lines = content.strip().splitlines() if content.strip() else []
        tool_name = f.stem.replace(".err", "")
        is_timeout = any("timeout" in ln.lower() for ln in lines)
        errors.append({
            "tool": tool_name,
            "file": str(f.relative_to(scan_dir)),
            "size_bytes": f.stat().st_size,
            "is_timeout": is_timeout,
            "lines": lines[:300],
            "line_count": len(lines),
            "has_content": bool(content.strip()),
        })
    timeouts = [e for e in errors if e.get("is_timeout")]
    return {
        "errors": errors,
        "total": len(errors),
        "timeouts": timeouts,
        "timeout_count": len(timeouts),
    }


# ---------------------------------------------------------------------------
# Overview summary
# ---------------------------------------------------------------------------

def build_overview(domain: str, scan_id: int) -> Dict[str, Any]:
    """Return a per-module count summary without loading full file data."""
    scan_dir = find_scan_dir(domain, scan_id)
    if not scan_dir:
        return {"status": "not_found", "scan_id": scan_id, "domain": domain}

    files = collect_files(scan_dir)
    counts: Dict[str, int] = {}
    for f in files:
        mod = route_file(f.name)
        if mod:
            counts[mod] = counts.get(mod, 0) + 1

    return {
        "status": "ok",
        "scan_id": scan_id,
        "domain": domain,
        "scan_dir": str(scan_dir),
        "total_files": len(files),
        "modules": counts,
        "module_count": len(counts),
    }


# ---------------------------------------------------------------------------
# Backward-compatibility shim (keeps existing /output-data endpoint working)
# ---------------------------------------------------------------------------

def get_dashboard_output_data(domain: str, scan_id: int) -> Optional[Dict[str, Any]]:
    """Legacy entry-point — calls ingest_scan and wraps result."""
    ingested = ingest_scan(domain, scan_id)
    if not ingested:
        return None
    return {
        "status": "success",
        "scan_id": scan_id,
        "domain": domain,
        "scan_dir": ingested["scan_dir"],
        "total_files": ingested["file_count"],
        "module_count": ingested["module_count"],
        "modules": {
            mod: {
                "module": mod,
                "file_count": len(files),
                "status": "has_data",
                "files": [{"filename": f["filename"], "ext": f["ext"], "size_bytes": f["size_bytes"]} for f in files],
            }
            for mod, files in ingested["modules"].items()
        },
        "unrouted_files": ingested.get("unrouted", []),
    }

