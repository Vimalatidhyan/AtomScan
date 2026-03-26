"""Correlator for linking assets, vulnerabilities, and threat data."""
from typing import Dict
from sqlalchemy.orm import Session
import logging

logger = logging.getLogger(__name__)


class ThreatCorrelator:
    """Correlate vulnerabilities with external threat intelligence."""

    def __init__(self, db: Session):
        self.db = db

    def correlate_scan_run(self, scan_run_id: int) -> Dict:
        """Correlate all findings in a scan run with threat intel.

        Args:
            scan_run_id: Scan run to correlate

        Returns:
            Dict with correlation results and statistics
        """
        from app.db.models import Vulnerability, ThreatIntelData, ActiveExploit, MalwareIndicator

        vulnerabilities = self.db.query(Vulnerability).filter(
            Vulnerability.scan_run_id == scan_run_id
        ).all()

        correlations = []
        stats = {
            "total_vulnerabilities": len(vulnerabilities),
            "with_threat_intel": 0,
            "with_active_exploits": 0,
            "with_malware": 0
        }

        for vuln in vulnerabilities:
            correlation = {
                "vulnerability_id": vuln.id,
                "cve_id": vuln.cve_id,
                "threat_intel": [],
                "active_exploits": [],
                "malware_indicators": []
            }

            # Find threat intel by CVE
            if vuln.cve_id:
                threat_intel = self.db.query(ThreatIntelData).filter(
                    ThreatIntelData.indicator_value.contains(vuln.cve_id)
                ).all()

                if threat_intel:
                    correlation["threat_intel"] = [
                        {
                            "source": ti.source,
                            "indicator_type": ti.indicator_type,
                            "severity": ti.severity
                        }
                        for ti in threat_intel
                    ]
                    stats["with_threat_intel"] += 1

            # Find active exploits
            active_exploits = self.db.query(ActiveExploit).filter(
                ActiveExploit.vulnerability_id == vuln.id
            ).all()

            if active_exploits:
                correlation["active_exploits"] = [
                    {
                        "exploit_name": ae.exploit_name,
                        "exploit_type": ae.exploit_type,
                        "source": ae.source_url
                    }
                    for ae in active_exploits
                ]
                stats["with_active_exploits"] += 1

            # Find malware indicators targeting this asset
            if vuln.subdomain_id:
                malware = self.db.query(MalwareIndicator).filter(
                    MalwareIndicator.scan_run_id == scan_run_id
                ).all()

                if malware:
                    correlation["malware_indicators"] = [
                        {
                            "indicator_type": mi.indicator_type,
                            "malware_family": mi.malware_family,
                            "verdict": mi.verdict
                        }
                        for mi in malware
                    ]
                    stats["with_malware"] += 1

            if correlation["threat_intel"] or correlation["active_exploits"] or correlation["malware_indicators"]:
                correlations.append(correlation)

        logger.info(f"Correlated {len(correlations)} vulnerabilities with threat intel for scan {scan_run_id}")

        return {
            "scan_run_id": scan_run_id,
            "statistics": stats,
            "correlations": correlations
        }

    def correlate_by_asset(self, asset_id: int, asset_type: str) -> Dict:
        """Correlate threats for a specific asset.

        Args:
            asset_id: Asset identifier
            asset_type: 'subdomain', 'port_scan', 'dns_record', etc.

        Returns:
            Dict with asset-specific correlation data
        """
        from app.db.models import Vulnerability

        # Find vulnerabilities affecting this asset
        if asset_type == "subdomain":
            vulnerabilities = self.db.query(Vulnerability).filter(
                Vulnerability.subdomain_id == asset_id
            ).all()
        elif asset_type == "port_scan":
            vulnerabilities = self.db.query(Vulnerability).filter(
                Vulnerability.port_scan_id == asset_id
            ).all()
        else:
            logger.warning(f"Unsupported asset type: {asset_type}")
            return {"error": "Unsupported asset type"}

        # Reuse scan run correlation logic
        if not vulnerabilities:
            return {
                "asset_id": asset_id,
                "asset_type": asset_type,
                "vulnerabilities": 0,
                "correlations": []
            }

        # Get unique scan run IDs and correlate each
        scan_run_ids = list(set(v.scan_run_id for v in vulnerabilities))
        all_correlations = []

        for scan_run_id in scan_run_ids:
            result = self.correlate_scan_run(scan_run_id)
            # Filter to only this asset's vulnerabilities
            asset_vuln_ids = {v.id for v in vulnerabilities if v.scan_run_id == scan_run_id}
            filtered = [c for c in result["correlations"] if c["vulnerability_id"] in asset_vuln_ids]
            all_correlations.extend(filtered)

        return {
            "asset_id": asset_id,
            "asset_type": asset_type,
            "vulnerabilities": len(vulnerabilities),
            "correlations": all_correlations
        }


def correlate_findings(db: Session, scan_run_id: int) -> Dict:
    """Convenience function to correlate a scan run.

    Args:
        db: Database session
        scan_run_id: Scan run to correlate

    Returns:
        Correlation results
    """
    correlator = ThreatCorrelator(db)
    return correlator.correlate_scan_run(scan_run_id)
