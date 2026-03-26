"""Main risk scoring orchestrator."""
from typing import Dict, List
from datetime import datetime
import logging

from intelligence.risk_scoring.epss import EPSSClient
from intelligence.risk_scoring.kev import KEVChecker
from intelligence.risk_scoring.business_context import BusinessContextScorer

logger = logging.getLogger(__name__)


def _age_penalty(discovered_at: datetime) -> int:
    days = (datetime.utcnow() - discovered_at).days
    if days < 30: return 0  # noqa: E701
    if days < 90: return -5  # noqa: E701
    if days < 365: return -10  # noqa: E701
    if days < 730: return -15  # noqa: E701
    return -20


def calculate_risk_scores(
    findings: List[Dict],
    assets: List[Dict],
    asset_metadata: Dict,
    kev_data: Dict,
    epss_data: Dict,
    threat_intel: List[Dict],
) -> Dict[int, int]:
    """Calculate final risk score for each finding (0-100)."""
    epss_client = EPSSClient()  # noqa: F841
    kev_checker = KEVChecker()  # noqa: F841
    bcs = BusinessContextScorer(asset_metadata)
    asset_criticality = bcs.calculate_criticality() / 100.0

    scores: Dict[int, int] = {}

    for finding in findings:
        fid = finding.get("id", 0)
        cvss_score = finding.get("cvss_score", 5.0)
        cve_ids = finding.get("cve_ids", "").split(",") if finding.get("cve_ids") else []
        discovered_at = finding.get("discovered_at", datetime.utcnow())
        internet_facing = finding.get("internet_facing", False)

        base_score = (cvss_score / 10.0) * 40

        # EPSS factor
        epss_score = 0.0
        for cve in cve_ids:
            cve = cve.strip()
            if cve:
                cached = epss_data.get(cve) or {}
                epss_score = max(epss_score, float(cached.get("epss", 0.0)))
        epss_factor = epss_score * 20

        # KEV bonus
        in_kev = any(kev_data.get(cve.strip()) for cve in cve_ids if cve.strip())
        kev_bonus = 25 if in_kev else 0

        # Threat intel bonus
        ti_bonus = 0
        for ti in threat_intel:
            if ti.get("active_exploitation"):
                ti_bonus += 10
                break
        if any(ti.get("public_exploit") for ti in threat_intel):
            ti_bonus += 5

        age_factor = _age_penalty(discovered_at) if isinstance(discovered_at, datetime) else 0
        exposure_mult = 1.3 if internet_facing else 1.0
        criticality_mult = 1.0 + (asset_criticality * 0.5)

        raw = (base_score + epss_factor + kev_bonus + ti_bonus) * criticality_mult * exposure_mult + age_factor
        scores[fid] = max(0, min(100, round(raw)))
        logger.debug(f"Finding {fid}: base={base_score:.1f} epss={epss_factor:.1f} kev={kev_bonus} ti={ti_bonus} -> {scores[fid]}")

    return scores
