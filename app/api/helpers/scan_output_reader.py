"""Scan output directory reader.

Parses raw scan output files (httpx, nmap, nikto, sslyze, etc.) to
supplement database records for the attack graph when DB tables are sparse.
"""
from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Base output directory relative to project root
OUTPUT_DIR = Path(__file__).resolve().parents[3] / "output"


def _sanitize_domain(domain: str) -> str:
    """Convert domain to the underscore form used in output dir names."""
    return domain.replace(".", "_").replace("-", "_")


def find_scan_dir(domain: str, scan_id: int) -> Optional[Path]:
    """Locate the output directory for a given domain + scan ID.

    Tries patterns like:
      output/{domain_underscored}_scan_{id}
      output/{domain_underscored}_{id}
    """
    base = _sanitize_domain(domain)
    candidates = [
        OUTPUT_DIR / f"{base}_scan_{scan_id}",
        OUTPUT_DIR / f"{base}_{scan_id}",
    ]
    for c in candidates:
        if c.is_dir():
            return c
    # Glob fallback
    for d in OUTPUT_DIR.glob(f"{base}*"):
        if d.is_dir() and str(scan_id) in d.name:
            return d
    return None


# ── Individual Parsers ─────────────────────────────────────────────────────────

def parse_httpx(scan_dir: Path) -> List[Dict[str, Any]]:
    """Parse httpx_alive.json (JSONL).  Returns list of host records."""
    httpx_file = scan_dir / "httpx_alive.json"
    if not httpx_file.exists():
        return []
    results = []
    with open(httpx_file, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return results


def parse_nmap_xml(scan_dir: Path) -> List[Dict[str, Any]]:
    """Parse nmap XML (looks in multiple locations).
    Returns list of {ip, hostname, port, protocol, service, version, state}."""
    candidates = [
        scan_dir / "nmap.xml",
        scan_dir / "phase2_intel" / "ports" / "nmap_all.xml",
    ]
    results = []
    for xml_path in candidates:
        if not xml_path.exists():
            continue
        try:
            tree = ET.parse(str(xml_path))
            root = tree.getroot()
            for host in root.findall("host"):
                addr = host.find("address")
                ip = addr.get("addr", "unknown") if addr is not None else "unknown"
                hostnames_el = host.find("hostnames")
                hostname = ""
                if hostnames_el is not None:
                    hn = hostnames_el.find("hostname")
                    if hn is not None:
                        hostname = hn.get("name", "")
                ports_el = host.find("ports")
                if ports_el is None:
                    continue
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    if state_el is None:
                        continue
                    pstate = state_el.get("state", "")
                    service_el = port_el.find("service")
                    svc_name = service_el.get("name", "") if service_el is not None else ""
                    svc_product = service_el.get("product", "") if service_el is not None else ""
                    svc_version = service_el.get("version", "") if service_el is not None else ""
                    results.append({
                        "ip": ip,
                        "hostname": hostname,
                        "port": int(port_el.get("portid", 0)),
                        "protocol": port_el.get("protocol", "tcp"),
                        "service": svc_name,
                        "version": f"{svc_product} {svc_version}".strip(),
                        "state": pstate,
                    })
        except Exception:
            continue
    return results


def parse_nikto(scan_dir: Path) -> List[Dict[str, Any]]:
    """Parse nikto_all.json (JSONL, each line = one host's findings)."""
    path = scan_dir / "phase4_vulnscan" / "misc" / "nikto_all.json"
    if not path.exists():
        return []
    all_findings = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                host = entry.get("host", "")
                ip = entry.get("ip", "")
                banner = entry.get("banner", "")
                port = entry.get("port", "")
                for v in entry.get("vulnerabilities", []):
                    all_findings.append({
                        "host": host,
                        "ip": ip,
                        "port": port,
                        "banner": banner,
                        "vuln_id": v.get("id", ""),
                        "method": v.get("method", ""),
                        "url": v.get("url", ""),
                        "msg": v.get("msg", ""),
                        "references": v.get("references", ""),
                    })
            except json.JSONDecodeError:
                continue
    return all_findings


def parse_ssl_findings(scan_dir: Path) -> List[Dict[str, Any]]:
    """Parse individual sslyze JSON files for SSL certificate summaries."""
    ssl_dir = scan_dir / "phase4_vulnscan" / "ssl"
    if not ssl_dir.exists():
        return []

    results = []
    # Parse individual host sslyze files (skip sslyze_all.json — too large)
    for ssl_file in sorted(ssl_dir.glob("sslyze_*.json")):
        if "sslyze_all" in ssl_file.name:
            continue
        try:
            with open(ssl_file, encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            scans = []
            if isinstance(data, dict):
                scans = data.get("server_scan_results", [data])
            elif isinstance(data, list):
                scans = data

            for scan in scans[:1]:  # just first result per file
                server = scan.get("server_location", scan.get("server_info", {}))
                hostname = ""
                ip = ""
                if isinstance(server, dict):
                    hostname = server.get("hostname", "")
                    ip = server.get("ip_address", "")
                if not hostname:
                    # Extract from filename
                    name_part = ssl_file.stem.replace("sslyze_", "").replace("_", ".")
                    hostname = name_part

                results.append({
                    "hostname": hostname,
                    "ip": ip,
                    "type": "ssl_cert",
                    "source": "sslyze",
                })
        except Exception:
            continue

    return results


def parse_ips_and_asn(scan_dir: Path) -> Tuple[List[str], List[Dict[str, Any]]]:
    """Parse all_ips.txt and asn_summary.txt."""
    ips_file = scan_dir / "phase2_intel" / "osint" / "all_ips.txt"
    asn_file = scan_dir / "phase2_intel" / "osint" / "asn_summary.txt"

    ips = []
    if ips_file.exists():
        with open(ips_file, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
                    ips.append(line)

    asn_data = []
    if asn_file.exists():
        with open(asn_file, encoding="utf-8", errors="ignore") as f:
            content = f.read()
            for match in re.finditer(r"\s+(\d+)\s+(AS\d+)", content):
                asn_data.append({"count": int(match.group(1)), "asn": match.group(2)})

    return ips, asn_data


def parse_threat_intel_summary(scan_dir: Path) -> Dict[str, Any]:
    """Parse threat_intel_summary.json."""
    for name in ("threat_intel_summary.json",
                 "phase5_threat_intel/phase5_threat_intel_summary.json"):
        path = scan_dir / name
        if path.exists():
            try:
                with open(path, encoding="utf-8", errors="ignore") as f:
                    return json.load(f)
            except Exception:
                pass
    return {}


def parse_compliance_summary(scan_dir: Path) -> Dict[str, Any]:
    """Parse compliance_summary.json."""
    path = scan_dir / "compliance_summary.json"
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return json.load(f)
    except Exception:
        return {}


def parse_risk_summary(scan_dir: Path) -> Dict[str, Any]:
    """Parse risk_summary.json."""
    path = scan_dir / "risk_summary.json"
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return json.load(f)
    except Exception:
        return {}


def parse_cve_matches(scan_dir: Path) -> List[Dict[str, Any]]:
    """Parse cve_matches.json."""
    path = scan_dir / "cve_matches.json"
    if not path.exists():
        return []
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def parse_content_discovery(scan_dir: Path) -> List[Dict[str, Any]]:
    """Parse directory brute-force / URL discovery results (ffuf JSON)."""
    results = []
    seen: set = set()

    for ffuf_file in sorted(scan_dir.glob("ffuf_*.json"))[:20]:
        if "ffuf_all" in ffuf_file.name:
            continue
        try:
            with open(ffuf_file, encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            for r in data.get("results", [])[:50]:
                url = r.get("url", "")
                status = r.get("status", 0)
                length = r.get("length", 0)
                if url and status in (200, 301, 302, 403) and url not in seen:
                    seen.add(url)
                    results.append({
                        "url": url,
                        "status": status,
                        "length": length,
                        "source": "ffuf",
                    })
        except Exception:
            continue

    return results[:100]


def load_all_scan_data(domain: str, scan_id: int) -> Optional[Dict[str, Any]]:
    """Load all available scan data from output files.

    Returns None if no scan directory is found.
    Returns a dictionary with enrichment data.
    """
    scan_dir = find_scan_dir(domain, scan_id)
    if scan_dir is None:
        return None

    httpx_data = parse_httpx(scan_dir)
    nmap_data = parse_nmap_xml(scan_dir)
    nikto_data = parse_nikto(scan_dir)
    ssl_data = parse_ssl_findings(scan_dir)
    ips, asn_data = parse_ips_and_asn(scan_dir)
    threat_intel = parse_threat_intel_summary(scan_dir)
    compliance = parse_compliance_summary(scan_dir)
    risk = parse_risk_summary(scan_dir)
    cve_matches = parse_cve_matches(scan_dir)
    content_disc = parse_content_discovery(scan_dir)

    # Collect unique technologies from httpx
    technologies: set = set()
    host_techs: Dict[str, set] = {}
    host_ips: Dict[str, set] = {}
    host_info: Dict[str, Dict] = {}
    for entry in httpx_data:
        host = entry.get("host", entry.get("input", ""))
        for t in entry.get("tech", []):
            technologies.add(t)
            host_techs.setdefault(host, set()).add(t)
        for a in entry.get("a", []):
            host_ips.setdefault(host, set()).add(a)
        if entry.get("host_ip"):
            host_ips.setdefault(host, set()).add(entry["host_ip"])
        host_info[host] = {
            "title": entry.get("title", ""),
            "status_code": entry.get("status_code"),
            "scheme": entry.get("scheme", ""),
            "content_type": entry.get("content_type", ""),
            "url": entry.get("url", ""),
        }

    return {
        "scan_dir": str(scan_dir),
        "httpx": httpx_data,
        "nmap": nmap_data,
        "nikto": nikto_data,
        "ssl": ssl_data,
        "ips": ips,
        "asn": asn_data,
        "threat_intel": threat_intel,
        "compliance": compliance,
        "risk": risk,
        "cve_matches": cve_matches,
        "content_discovery": content_disc,
        "technologies": list(technologies),
        "host_techs": {k: list(v) for k, v in host_techs.items()},
        "host_ips": {k: list(v) for k, v in host_ips.items()},
        "host_info": host_info,
    }
