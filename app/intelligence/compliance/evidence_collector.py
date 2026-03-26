"""Compliance evidence collector — gathers artifacts that demonstrate control compliance."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


class EvidenceCollector:
    """Collects and stores evidence artefacts for compliance controls."""

    def __init__(self, evidence_dir: str = "evidence"):
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    # ── public API ───────────────────────────────────────────────────────────

    def collect(
        self,
        scan_results: Dict[str, Any],
        framework: str = "all",
        scan_run_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Collect evidence from *scan_results* and persist to disk."""
        evidence: Dict[str, Any] = {
            "framework": framework,
            "scan_run_id": scan_run_id,
            "collected_at": datetime.utcnow().isoformat() + "Z",
            "artefacts": [],
        }

        evidence["artefacts"].extend(self._collect_tls_evidence(scan_results))
        evidence["artefacts"].extend(self._collect_vuln_evidence(scan_results))
        evidence["artefacts"].extend(self._collect_access_evidence(scan_results))
        evidence["artefacts"].extend(self._collect_network_evidence(scan_results))

        self._persist(evidence, framework)
        return evidence

    def load(self, framework: str) -> List[Dict[str, Any]]:
        """Load persisted evidence artefacts for *framework*."""
        path = self.evidence_dir / f"{framework}_evidence.json"
        if path.exists():
            with open(path) as f:
                return json.load(f).get("artefacts", [])
        return []

    # ── private helpers ──────────────────────────────────────────────────────

    def _collect_tls_evidence(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        artefacts: List[Dict[str, Any]] = []
        for issue in results.get("tls_issues", []):
            artefacts.append({
                "type": "tls",
                "control": "encryption_in_transit",
                "severity": issue.get("severity", "unknown"),
                "detail": issue.get("finding", issue.get("description", "")),
                "pass": issue.get("severity", "").upper() not in ("HIGH", "CRITICAL"),
            })
        return artefacts

    def _collect_vuln_evidence(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        artefacts: List[Dict[str, Any]] = []
        for vuln in results.get("vulnerabilities", []):
            severity = vuln.get("severity", "unknown").lower()
            artefacts.append({
                "type": "vulnerability",
                "control": "vulnerability_management",
                "severity": severity,
                "detail": vuln.get("name", vuln.get("id", "")),
                "pass": severity not in ("critical", "high"),
            })
        return artefacts

    def _collect_access_evidence(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        artefacts: List[Dict[str, Any]] = []
        for port in results.get("open_ports", []):
            risky_ports = {21, 23, 445, 3389, 5900}
            p = int(port.get("port", 0))
            if p in risky_ports:
                artefacts.append({
                    "type": "exposed_port",
                    "control": "access_control",
                    "severity": "high",
                    "detail": f"Risky port {p}/{port.get('protocol', 'tcp')} exposed",
                    "pass": False,
                })
        return artefacts

    def _collect_network_evidence(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        artefacts: List[Dict[str, Any]] = []
        subdomains = results.get("subdomains", [])
        artefacts.append({
            "type": "asset_inventory",
            "control": "asset_management",
            "severity": "info",
            "detail": f"{len(subdomains)} subdomains discovered",
            "pass": True,
        })
        return artefacts

    def _persist(self, evidence: Dict[str, Any], framework: str) -> None:
        path = self.evidence_dir / f"{framework}_evidence.json"
        with open(path, "w") as f:
            json.dump(evidence, f, indent=2)


def collect_compliance_evidence(
    scan_results: Dict[str, Any],
    framework: str = "all",
    evidence_dir: str = "evidence",
    scan_run_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Convenience wrapper around :class:`EvidenceCollector`."""
    return EvidenceCollector(evidence_dir).collect(scan_results, framework, scan_run_id)
