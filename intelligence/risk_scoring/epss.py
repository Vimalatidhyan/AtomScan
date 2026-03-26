"""EPSS API client for exploit probability scoring."""
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class EPSSClient:
    """Query EPSS API for exploitation probability scores."""

    BASE_URL = "https://api.first.org/data/v1/epss/by-cve"
    _cache: Dict[str, Dict] = {}

    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key

    def lookup_cve(self, cve_id: str) -> Optional[Dict]:
        """Query EPSS API for a CVE. Returns cached data or default on failure."""
        if cve_id in self._cache:
            return self._cache[cve_id]
        try:
            import urllib.request
            import json as j
            url = f"{self.BASE_URL}?cve={cve_id}"
            with urllib.request.urlopen(url, timeout=5) as resp:
                data = j.loads(resp.read())
                if data.get("data"):
                    result = data["data"][0]
                    self._cache[cve_id] = result
                    return result
        except Exception as e:
            logger.debug(f"EPSS lookup failed for {cve_id}: {e}")
        return {"cve": cve_id, "epss": 0.0, "percentile": 0.0, "date": ""}

    def lookup_multiple(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """Batch lookup for multiple CVEs."""
        return {cve: self.lookup_cve(cve) for cve in cve_ids}

    def score_to_severity(self, epss_score: float) -> str:
        """Convert EPSS score (0-1) to severity label."""
        if epss_score >= 0.8: return "critical"  # noqa: E701
        if epss_score >= 0.5: return "high"  # noqa: E701
        if epss_score >= 0.2: return "medium"  # noqa: E701
        return "low"
