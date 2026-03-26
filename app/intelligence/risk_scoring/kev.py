"""CISA Known Exploited Vulnerabilities (KEV) checker."""
from typing import Dict, List, Optional
from pathlib import Path
import json
import logging

logger = logging.getLogger(__name__)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_PATH = Path("data/threat_feeds/cisa_kev.json")

class KEVChecker:
    """Check if vulnerabilities are in CISA KEV catalog."""

    def __init__(self) -> None:
        self._catalog: Dict[str, Dict] = {}
        self._load()

    def _load(self) -> None:
        if KEV_CACHE_PATH.exists():
            try:
                data = json.loads(KEV_CACHE_PATH.read_text())
                for vuln in data.get("vulnerabilities", []):
                    self._catalog[vuln["cveID"]] = vuln
                logger.info(f"Loaded {len(self._catalog)} KEV entries")
            except Exception as e:
                logger.warning(f"KEV cache load failed: {e}")

    def check_cve(self, cve_id: str) -> Optional[Dict]:
        """Check if CVE is in CISA KEV catalog."""
        entry = self._catalog.get(cve_id)
        if not entry:
            return None
        return {
            "cve_id": cve_id,
            "in_kev": True,
            "date_added": entry.get("dateAdded", ""),
            "vendor": entry.get("vendorProject", ""),
            "product": entry.get("product", ""),
            "notes": entry.get("notes", ""),
        }

    def update_kev_feed(self) -> int:
        """Download and cache CISA KEV feed. Returns count of entries."""
        try:
            import urllib.request
            with urllib.request.urlopen(KEV_URL, timeout=15) as resp:  # nosec B310
                data = json.loads(resp.read())
            KEV_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            KEV_CACHE_PATH.write_text(json.dumps(data, indent=2))
            for vuln in data.get("vulnerabilities", []):
                self._catalog[vuln["cveID"]] = vuln
            logger.info(f"Updated KEV feed: {len(self._catalog)} entries")
            return len(self._catalog)
        except Exception as e:
            logger.error(f"KEV feed update failed: {e}")
            return 0

    def get_latest_kev(self, limit: int = 20) -> List[Dict]:
        """Get recently added KEV entries."""
        entries = sorted(self._catalog.values(), key=lambda x: x.get("dateAdded", ""), reverse=True)
        return entries[:limit]
