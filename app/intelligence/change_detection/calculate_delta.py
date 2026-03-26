"""Delta calculator for change detection between scan baselines."""
from typing import Any, Dict


def calculate_delta(baseline: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two scan snapshots and return all detected changes."""
    b_subs = set(baseline.get("subdomains", []))
    c_subs = set(current.get("subdomains", []))
    b_ports = set(baseline.get("ports", []))
    c_ports = set(current.get("ports", []))
    b_vulns = {v["id"]: v for v in baseline.get("vulnerabilities", [])}
    c_vulns = {v["id"]: v for v in current.get("vulnerabilities", [])}

    new_assets = [{"type": "subdomain", "value": s} for s in (c_subs - b_subs)]
    removed_assets = [{"type": "subdomain", "value": s} for s in (b_subs - c_subs)]
    new_ports = [{"type": "port", "value": p} for p in (c_ports - b_ports)]
    closed_ports = [{"type": "port", "value": p} for p in (b_ports - c_ports)]
    new_vulns = [c_vulns[vid] for vid in (set(c_vulns) - set(b_vulns))]
    resolved_vulns = [b_vulns[vid] for vid in (set(b_vulns) - set(c_vulns))]

    changed_severity = []
    for vid in set(b_vulns) & set(c_vulns):
        if b_vulns[vid].get("severity") != c_vulns[vid].get("severity"):
            changed_severity.append({"vuln_id": vid, "old": b_vulns[vid].get("severity"), "new": c_vulns[vid].get("severity")})

    total = len(new_assets) + len(removed_assets) + len(new_vulns) + len(resolved_vulns) + len(changed_severity)
    critical_changes = len([v for v in new_vulns if (v.get("severity") or 0) >= 90])

    return {
        "new_assets": new_assets,
        "removed_assets": removed_assets,
        "new_ports": new_ports,
        "closed_ports": closed_ports,
        "new_vulnerabilities": new_vulns,
        "resolved_vulnerabilities": resolved_vulns,
        "changed_severity": changed_severity,
        "summary": {
            "total_changes": total,
            "critical_changes": critical_changes,
            "assets_added": len(new_assets),
            "assets_removed": len(removed_assets),
            "vulns_added": len(new_vulns),
            "vulns_resolved": len(resolved_vulns),
        },
    }
