"""Asset management API routes.

Route order: static/specific paths before parameterised paths.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, distinct
from typing import Optional

from app.db.database import get_db
from app.db.models import (
    Subdomain, ScanRun, Vulnerability, PortScan,
    DNSRecord, DomainTechnology, Technology, ThreatIntelData,
    ISPLocation, ComplianceReport, ComplianceFinding, RiskScore,
    HTTPHeader, ScanEvent,
)
from app.api.models.asset import AssetListResponse, AssetResponse
from app.api.models.common import StatusResponse

router = APIRouter()


# ── Static / aggregate routes (must precede /{asset_id}) ────────────────────

@router.get("/targets", summary="List distinct target domains")
def list_targets(db: Session = Depends(get_db)):
    """Return all distinct target domains that have been scanned."""
    rows = db.query(distinct(ScanRun.domain)).all()
    targets = [r[0] for r in rows if r[0]]
    return {"targets": targets, "total": len(targets)}


@router.get("/stats/{target:path}", summary="Asset stats for a target domain")
def asset_stats(target: str, db: Session = Depends(get_db)):
    """Return aggregated asset and finding stats for a target domain."""
    scan = (
        db.query(ScanRun)
        .filter(ScanRun.domain == target)
        .order_by(ScanRun.id.desc())
        .first()
    )
    if not scan:
        return {"target": target, "assets": 0, "subdomains": 0, "ports": 0, "vulnerabilities": 0,
                "critical": 0, "high": 0, "medium": 0, "low": 0}

    subdomain_count = db.query(func.count(Subdomain.id)).filter(
        Subdomain.scan_run_id == scan.id
    ).scalar() or 0
    port_count = (
        db.query(func.count(PortScan.id))
        .join(Subdomain, Subdomain.id == PortScan.subdomain_id)
        .filter(Subdomain.scan_run_id == scan.id, PortScan.state == "open")
        .scalar()
        or 0
    )

    vulns = db.query(Vulnerability).filter(Vulnerability.scan_run_id == scan.id).all()
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        sev = v.severity or 0
        if sev >= 90:
            counts["critical"] += 1
        elif sev >= 70:
            counts["high"] += 1
        elif sev >= 40:
            counts["medium"] += 1
        else:
            counts["low"] += 1

    # Cloud assets count from ScanEvent
    cloud_assets = 0
    cloud_ev = (
        db.query(ScanEvent)
        .filter(ScanEvent.scan_run_id == scan.id, ScanEvent.event_type == "cloud_data")
        .order_by(ScanEvent.id.desc())
        .first()
    )
    if cloud_ev and cloud_ev.data:
        import json as _json
        try:
            cloud_assets = _json.loads(cloud_ev.data).get("total", 0)
        except (ValueError, TypeError):
            pass

    return {
        "target": target,
        "assets": subdomain_count,
        "subdomains": subdomain_count,
        "ports": port_count,
        "vulnerabilities": len(vulns),
        "cloud_assets": cloud_assets,
        **counts,
    }


@router.get("/search", response_model=AssetListResponse, summary="Search assets")
def search_assets(
    q_str: str = Query(..., alias="q"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20),
    db: Session = Depends(get_db),
):
    q = db.query(Subdomain).filter(Subdomain.subdomain.contains(q_str))
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()
    return AssetListResponse(total=total, page=page, per_page=per_page, items=items)


@router.get("/by-domain/{domain}", response_model=AssetListResponse, summary="Assets by domain")
def assets_by_domain(
    domain: str,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    q = db.query(Subdomain).filter(Subdomain.subdomain.contains(domain))
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()
    return AssetListResponse(total=total, page=page, per_page=per_page, items=items)


@router.get("/subdomains/{target:path}", summary="Subdomains for a target domain")
def get_subdomains(target: str, db: Session = Depends(get_db)):
    """Return all subdomains discovered for the given target domain (most recent scan)."""
    scan = (
        db.query(ScanRun)
        .filter(ScanRun.domain == target)
        .order_by(ScanRun.id.desc())
        .first()
    )
    if not scan:
        return {"subdomains": [], "total": 0}
    items = db.query(Subdomain).filter(Subdomain.scan_run_id == scan.id).all()
    return {
        "subdomains": [
            {
                "subdomain": s.subdomain,
                "ip": None,
                "is_alive": s.is_alive,
                "first_seen": s.first_seen.isoformat() if s.first_seen else None,
                "last_seen": s.last_seen.isoformat() if s.last_seen else None,
            }
            for s in items
        ],
        "total": len(items),
    }


@router.get("/ports/{target:path}", summary="Open ports for a target domain")
def get_ports(target: str, db: Session = Depends(get_db)):
    """Return all port scan results for the given target domain (most recent scan)."""
    scan = (
        db.query(ScanRun)
        .filter(ScanRun.domain == target)
        .order_by(ScanRun.id.desc())
        .first()
    )
    if not scan:
        return {"ports": [], "total": 0}
    rows = (
        db.query(PortScan, Subdomain.subdomain)
        .join(Subdomain, PortScan.subdomain_id == Subdomain.id)
        .filter(Subdomain.scan_run_id == scan.id)
        .all()
    )
    return {
        "ports": [
            {
                "port": p.port,
                "protocol": p.protocol,
                "service": p.service,
                "subdomain": subdomain,
                "state": p.state,
            }
            for p, subdomain in rows
        ],
        "total": len(rows),
    }


@router.get("/graph/{target:path}", summary="Full attack graph data for a target")
def get_attack_graph(target: str, db: Session = Depends(get_db)):
    """Return all phase results aggregated into an attack graph structure.

    Combines data from:
    - Database tables (primary source)
    - Scan output files on disk (enrichment when DB data is sparse)

    Phases covered:
    - Phase 1: Subdomains (discovery)
    - Phase 2: DNS records, IPs, ISP/ASN info (intel)
    - Phase 3: Technologies, HTTP headers (content)
    - Phase 4: Vulnerabilities, ports, SSL, nikto findings (vulnscan)
    - Phase 5: Threat intel indicators
    - Phase 6: CVE correlation
    - Phase 7: Compliance reports
    - Phase 8: Risk scores
    """
    from app.api.helpers.scan_output_reader import load_all_scan_data

    scan = (
        db.query(ScanRun)
        .filter(ScanRun.domain == target)
        .order_by(ScanRun.id.desc())
        .first()
    )
    if not scan:
        return {
            "target": target, "scan_id": None, "status": "not_found",
            "phases": {}, "nodes": [], "edges": [],
        }

    # Load file-based enrichment data
    file_data = load_all_scan_data(target, scan.id)

    # Severity label helper
    def sev_label(val):
        if val is None:
            return "info"
        if isinstance(val, str):
            return val.lower() if val.lower() in ("critical", "high", "medium", "low") else "info"
        if val >= 90:
            return "critical"
        if val >= 70:
            return "high"
        if val >= 40:
            return "medium"
        if val >= 10:
            return "low"
        return "info"

    nodes = []
    edges = []
    node_ids = set()
    edge_set = set()  # prevent duplicate edges

    def add_node(ntype, identifier, phase, **props):
        nid = f"{ntype}:{identifier}"
        if nid in node_ids:
            return nid
        node_ids.add(nid)
        nodes.append({"id": nid, "type": ntype, "label": identifier, "phase": phase, **props})
        return nid

    def add_edge(src, tgt, rel_type, **props):
        key = (src, tgt, rel_type)
        if key in edge_set:
            return
        edge_set.add(key)
        edges.append({"source": src, "target": tgt, "type": rel_type, **props})

    # Root target
    root_id = add_node("target", target, "root", is_root=True)

    # ── Phase 1: Discovery (subdomains) ──────────────────────────────────
    subdomains_orm = db.query(Subdomain).filter(Subdomain.scan_run_id == scan.id).all()
    sub_map = {}  # subdomain_string -> node_id  AND  db_id -> node_id
    phase1_data = []
    for s in subdomains_orm:
        sid = add_node("subdomain", s.subdomain, "phase1_discovery",
                       is_alive=s.is_alive,
                       discovered_method=s.discovered_method,
                       first_seen=s.first_seen.isoformat() if s.first_seen else None)
        sub_map[s.subdomain] = sid
        sub_map[s.id] = sid
        add_edge(root_id, sid, "HAS_SUBDOMAIN")
        phase1_data.append({"subdomain": s.subdomain, "is_alive": s.is_alive})

    # ── Phase 2: Intel (DNS, IPs, ASN) ───────────────────────────────────
    dns_records = db.query(DNSRecord).filter(DNSRecord.scan_run_id == scan.id).all()
    phase2_data = {"dns_records": [], "ip_locations": []}
    for d in dns_records:
        dns_id = add_node("dns_record", f"{d.domain}:{d.record_type}:{d.value}", "phase2_intel",
                          record_type=d.record_type, value=d.value, domain=d.domain,
                          ttl=d.ttl)
        parent = sub_map.get(d.domain, root_id)
        add_edge(parent, dns_id, "HAS_DNS_RECORD")
        phase2_data["dns_records"].append({
            "domain": d.domain, "type": d.record_type, "value": d.value
        })
        if d.record_type in ("A", "AAAA"):
            ip_id = add_node("ip_address", d.value, "phase2_intel")
            add_edge(parent, ip_id, "RESOLVES_TO")

    isp_locations = db.query(ISPLocation).filter(ISPLocation.scan_run_id == scan.id).all()
    for loc in isp_locations:
        ip_id = add_node("ip_address", loc.ip_address, "phase2_intel",
                         isp=loc.isp_name, country=loc.country, city=loc.city)
        add_edge(root_id, ip_id, "HAS_IP")
        phase2_data["ip_locations"].append({
            "ip": loc.ip_address, "isp": loc.isp_name, "country": loc.country
        })

    # ── File enrichment: IPs from httpx + all_ips.txt ────────────────────
    file_ip_count = 0
    file_tech_count = 0
    file_port_count = 0
    file_vuln_count = 0
    file_ti_count = 0

    if file_data:
        # Add IPs from httpx (host_ips) — linked to their subdomains
        for host, ip_list in file_data.get("host_ips", {}).items():
            parent = sub_map.get(host, root_id)
            for ip in ip_list:
                ip_nid = add_node("ip_address", ip, "phase2_intel")
                add_edge(parent, ip_nid, "RESOLVES_TO")
                file_ip_count += 1

        # Add remaining IPs from all_ips.txt (direct to root)
        for ip in file_data.get("ips", []):
            nid = f"ip_address:{ip}"
            if nid not in node_ids:
                add_node("ip_address", ip, "phase2_intel")
                add_edge(root_id, nid, "HAS_IP")
                file_ip_count += 1

        # Add ASN info nodes
        for asn_entry in file_data.get("asn", []):
            asn_id = add_node("asn", asn_entry["asn"], "phase2_intel",
                              count=asn_entry["count"])
            add_edge(root_id, asn_id, "HAS_ASN")

    # ── Phase 3: Content (technologies) ──────────────────────────────────
    techs = (
        db.query(DomainTechnology, Technology)
        .join(Technology, DomainTechnology.technology_id == Technology.id)
        .filter(DomainTechnology.scan_run_id == scan.id)
        .all()
    )
    phase3_data = []
    for dt, tech in techs:
        tech_id = add_node("technology", tech.name, "phase3_content",
                           category=tech.category, version=dt.version,
                           confidence=dt.confidence)
        add_edge(root_id, tech_id, "USES_TECHNOLOGY")
        phase3_data.append({
            "name": tech.name, "category": tech.category, "version": dt.version
        })

    # HTTP headers from DB
    headers = (
        db.query(HTTPHeader, Subdomain.subdomain)
        .join(Subdomain, HTTPHeader.subdomain_id == Subdomain.id)
        .filter(Subdomain.scan_run_id == scan.id)
        .all()
    )
    header_groups = {}
    for h, sub_name in headers:
        header_groups.setdefault(sub_name, []).append({
            "name": h.header_name, "value": h.header_value
        })

    # ── File enrichment: technologies from httpx ─────────────────────────
    if file_data:
        # Per-host technologies
        for host, tech_list in file_data.get("host_techs", {}).items():
            parent = sub_map.get(host, root_id)
            for t in tech_list:
                tech_nid = add_node("technology", t, "phase3_content",
                                    category="detected", source="httpx")
                add_edge(parent, tech_nid, "USES_TECHNOLOGY")
                file_tech_count += 1

        # Host info (status codes, titles) — attach to subdomain nodes
        for host, info in file_data.get("host_info", {}).items():
            if host in sub_map:
                # Update existing subdomain node with httpx metadata
                for n in nodes:
                    if n["id"] == sub_map[host]:
                        n["title"] = info.get("title", "")
                        n["status_code"] = info.get("status_code")
                        n["url"] = info.get("url", "")
                        break

    # ── Phase 4: Vulnscan (ports & vulnerabilities) ──────────────────────
    ports_orm = (
        db.query(PortScan, Subdomain.subdomain)
        .join(Subdomain, PortScan.subdomain_id == Subdomain.id)
        .filter(Subdomain.scan_run_id == scan.id)
        .all()
    )
    port_map = {}
    phase4_ports = []
    for p, sub_name in ports_orm:
        port_id = add_node("port", f"{sub_name}:{p.port}/{p.protocol}", "phase4_vulnscan",
                           port=p.port, protocol=p.protocol, service=p.service,
                           version=p.version, state=p.state, host=sub_name)
        parent = sub_map.get(sub_name, root_id)
        add_edge(parent, port_id, "HAS_PORT")
        port_map[p.id] = port_id
        phase4_ports.append({
            "host": sub_name, "port": p.port, "service": p.service, "state": p.state
        })

    # DB vulnerabilities
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_run_id == scan.id).all()
    phase4_vulns = []
    for v in vulns:
        sv = sev_label(v.severity)
        vuln_id = add_node("vulnerability", f"vuln:{v.id}:{v.title or 'finding'}", "phase4_vulnscan",
                           severity=sv, severity_score=v.severity,
                           title=v.title, description=v.description,
                           cve=v.cve_ids, remediation=v.remediation,
                           vuln_type=v.vuln_type, status=v.status)
        if v.port_scan_id and v.port_scan_id in port_map:
            add_edge(port_map[v.port_scan_id], vuln_id, "IS_VULNERABLE_TO")
        elif v.subdomain_id and v.subdomain_id in sub_map:
            add_edge(sub_map[v.subdomain_id], vuln_id, "IS_VULNERABLE_TO")
        else:
            add_edge(root_id, vuln_id, "IS_VULNERABLE_TO")
        phase4_vulns.append({
            "title": v.title, "severity": sv, "cve": v.cve_ids, "type": v.vuln_type
        })

    # ── File enrichment: nmap ports ──────────────────────────────────────
    if file_data:
        for p in file_data.get("nmap", []):
            hostname = p.get("hostname", "")
            ip = p.get("ip", "")
            pnum = p.get("port", 0)
            proto = p.get("protocol", "tcp")
            svc = p.get("service", "")
            ver = p.get("version", "")
            pstate = p.get("state", "")
            label = f"{hostname or ip}:{pnum}/{proto}"
            port_nid = add_node("port", label, "phase4_vulnscan",
                                port=pnum, protocol=proto, service=svc,
                                version=ver, state=pstate,
                                host=hostname or ip)
            parent = sub_map.get(hostname, root_id)
            add_edge(parent, port_nid, "HAS_PORT")
            file_port_count += 1

        # Nikto findings → vulnerability nodes
        for nk in file_data.get("nikto", []):
            host = nk.get("host", "")
            msg = nk.get("msg", "")
            vid = nk.get("vuln_id", "")
            if not msg:
                continue
            vuln_label = f"nikto:{vid}:{msg[:60]}"
            vuln_nid = add_node("vulnerability", vuln_label, "phase4_vulnscan",
                                severity="medium",
                                title=msg[:120],
                                description=msg,
                                vuln_type="nikto",
                                references=nk.get("references", ""),
                                source="nikto",
                                host=host,
                                port=nk.get("port", ""),
                                banner=nk.get("banner", ""))
            parent = sub_map.get(host, root_id)
            add_edge(parent, vuln_nid, "IS_VULNERABLE_TO")
            file_vuln_count += 1

        # SSL certificate info as nodes
        for ssl in file_data.get("ssl", []):
            hostname = ssl.get("hostname", "")
            ssl_nid = add_node("ssl_cert", f"ssl:{hostname}", "phase4_vulnscan",
                               hostname=hostname,
                               ip=ssl.get("ip", ""),
                               source="sslyze")
            parent = sub_map.get(hostname, root_id)
            add_edge(parent, ssl_nid, "HAS_SSL_CERT")

        # Content discovery as URL nodes (phase3)
        for cd in file_data.get("content_discovery", [])[:50]:
            url = cd.get("url", "")
            status = cd.get("status", 0)
            if not url:
                continue
            url_nid = add_node("url", url, "phase3_content",
                               status_code=status,
                               length=cd.get("length", 0),
                               source=cd.get("source", ""))
            add_edge(root_id, url_nid, "HAS_URL")

    # ── Phase 5: Threat Intel ────────────────────────────────────────────
    threat_intel_orm = db.query(ThreatIntelData).all()
    scan_vuln_ids = {v.id for v in vulns}
    phase5_data = []
    for ti in threat_intel_orm:
        if ti.vulnerability_id and ti.vulnerability_id in scan_vuln_ids:
            ti_id = add_node("threat_intel", f"ti:{ti.id}:{ti.indicator_value}", "phase5_threat",
                             indicator_type=ti.indicator_type,
                             indicator_value=ti.indicator_value,
                             source=ti.source, severity=sev_label(ti.severity))
            vuln_node = f"vulnerability:vuln:{ti.vulnerability_id}:{next((v.title for v in vulns if v.id == ti.vulnerability_id), 'finding')}"
            if vuln_node in node_ids:
                add_edge(vuln_node, ti_id, "HAS_THREAT_INTEL")
            else:
                add_edge(root_id, ti_id, "HAS_THREAT_INTEL")
            phase5_data.append({
                "type": ti.indicator_type, "value": ti.indicator_value,
                "source": ti.source
            })

    # ── File enrichment: threat intel summary ────────────────────────────
    if file_data and file_data.get("threat_intel"):
        ti_summary = file_data["threat_intel"]
        total_threats = ti_summary.get("total_threats", 0)
        if total_threats > 0 and len(phase5_data) == 0:
            # Add summary threat intel node
            for ttype, tcount in ti_summary.get("by_type", {}).items():
                ti_nid = add_node("threat_intel", f"ti:file:{ttype}", "phase5_threat",
                                  indicator_type=ttype,
                                  indicator_value=f"{tcount} indicators",
                                  source="scan_output",
                                  severity=sev_label(ti_summary.get("critical", 0) * 100
                                                     if ti_summary.get("critical", 0) > 0
                                                     else ti_summary.get("high", 0) * 80
                                                     if ti_summary.get("high", 0) > 0
                                                     else 50))
                add_edge(root_id, ti_nid, "HAS_THREAT_INTEL")
                file_ti_count += 1

    # ── Phase 7: Compliance ──────────────────────────────────────────────
    compliance_reports = db.query(ComplianceReport).filter(
        ComplianceReport.scan_run_id == scan.id
    ).all()
    phase7_data = []
    for cr in compliance_reports:
        cr_id = add_node("compliance", f"compliance:{cr.id}:{cr.report_type}", "phase7_compliance",
                         report_type=cr.report_type,
                         passed=cr.passed_checks, failed=cr.failed_checks,
                         score=cr.overall_score)
        add_edge(root_id, cr_id, "HAS_COMPLIANCE_REPORT")
        phase7_data.append({
            "type": cr.report_type, "passed": cr.passed_checks,
            "failed": cr.failed_checks, "score": cr.overall_score
        })

    # ── File enrichment: compliance summary ──────────────────────────────
    if file_data and file_data.get("compliance") and len(phase7_data) == 0:
        comp = file_data["compliance"]
        for framework, info in comp.get("frameworks", {}).items():
            if isinstance(info, dict):
                cr_nid = add_node("compliance", f"compliance:file:{framework}", "phase7_compliance",
                                  report_type=framework,
                                  passed=0, failed=info.get("controls_failed", 0),
                                  score=info.get("compliance_percentage", 0),
                                  status=info.get("status", ""))
                add_edge(root_id, cr_nid, "HAS_COMPLIANCE_REPORT")

    # ── Phase 8: Risk Scores ─────────────────────────────────────────────
    risk_scores = db.query(RiskScore).filter(RiskScore.scan_run_id == scan.id).all()
    phase8_data = []
    for rs in risk_scores:
        phase8_data.append({
            "method": rs.calculation_method,
            "overall_score": rs.overall_score,
            "critical": rs.critical_count,
            "high": rs.high_count,
            "medium": rs.medium_count,
            "low": rs.low_count,
        })

    # ── Count all items for stats ────────────────────────────────────────
    total_subdomains = len(subdomains_orm)
    total_ports = len(ports_orm) + file_port_count
    total_vulns = len(vulns) + file_vuln_count
    total_techs = len(techs) + file_tech_count
    total_dns = len(dns_records) + file_ip_count
    total_ti = len(phase5_data) + file_ti_count
    total_compliance = len(compliance_reports)

    critical_count = sum(1 for v in vulns if (v.severity or 0) >= 90)
    high_count = sum(1 for v in vulns if 70 <= (v.severity or 0) < 90)

    # Build phase summary
    phases = {
        "phase1_discovery": {"label": "Discovery", "count": total_subdomains, "data": phase1_data},
        "phase2_intel": {"label": "Intel", "count": total_dns, "data": phase2_data},
        "phase3_content": {"label": "Content", "count": total_techs, "data": phase3_data},
        "phase4_vulnscan": {"label": "Vuln Scan", "count": total_ports + total_vulns,
                            "ports": phase4_ports, "vulnerabilities": phase4_vulns},
        "phase5_threat": {"label": "Threat Intel", "count": total_ti, "data": phase5_data},
        "phase7_compliance": {"label": "Compliance", "count": total_compliance, "data": phase7_data},
        "phase8_risk": {"label": "Risk Scoring", "count": len(risk_scores), "data": phase8_data},
    }

    return {
        "target": target,
        "scan_id": scan.id,
        "status": scan.status,
        "scan_type": scan.scan_type,
        "risk_score": scan.risk_score,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "phases": phases,
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "subdomains": total_subdomains,
            "ports": total_ports,
            "vulnerabilities": total_vulns,
            "critical": critical_count,
            "high": high_count,
            "technologies": total_techs,
            "dns_records": total_dns,
            "threat_indicators": total_ti,
            "compliance_reports": total_compliance,
        },
    }


@router.get("/high-risk", response_model=AssetListResponse, summary="High-risk assets")
def high_risk_assets(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    min_vulns: int = Query(5, ge=0),
    scan_run_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    vuln_counts = (
        db.query(
            Vulnerability.subdomain_id,
            func.count(Vulnerability.id).label("vuln_count"),
        )
        .group_by(Vulnerability.subdomain_id)
        .subquery()
    )
    q = (
        db.query(Subdomain)
        .join(vuln_counts, Subdomain.id == vuln_counts.c.subdomain_id)
        .filter(vuln_counts.c.vuln_count >= min_vulns, Subdomain.is_alive == True)
    )
    if scan_run_id:
        q = q.filter(Subdomain.scan_run_id == scan_run_id)
    total = q.count()
    items = (
        q.order_by(vuln_counts.c.vuln_count.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    return AssetListResponse(total=total, page=page, per_page=per_page, items=items)


@router.get("/", response_model=AssetListResponse, summary="List assets")
def list_assets(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    scan_run_id: Optional[int] = None,
    is_alive: Optional[bool] = None,
    db: Session = Depends(get_db),
):
    q = db.query(Subdomain)
    if scan_run_id:
        q = q.filter(Subdomain.scan_run_id == scan_run_id)
    if is_alive is not None:
        q = q.filter(Subdomain.is_alive == is_alive)
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()
    return AssetListResponse(total=total, page=page, per_page=per_page, items=items)


# ── Item routes (parameterised — must come AFTER static paths) ───────────────

@router.get("/{asset_id}", response_model=AssetResponse, summary="Get asset")
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Subdomain).filter(Subdomain.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.get("/{asset_id}/timeline", summary="Asset activity timeline")
def asset_timeline(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Subdomain).filter(Subdomain.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    vulns = (
        db.query(Vulnerability)
        .filter(Vulnerability.subdomain_id == asset_id)
        .order_by(Vulnerability.discovered_at.asc())
        .all()
    )
    events = [
        {
            "event_type": "vulnerability",
            "severity": v.severity,
            "title": v.title,
            "timestamp": v.discovered_at.isoformat() if v.discovered_at else None,
        }
        for v in vulns
    ]
    return {
        "asset_id": asset_id,
        "subdomain": asset.subdomain,
        "is_alive": asset.is_alive,
        "events": events,
        "total": len(events),
    }
