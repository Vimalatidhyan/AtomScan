"""AlienVault OTX API client."""
from typing import Dict, Optional
import logging
import urllib.request
import json

logger = logging.getLogger(__name__)
OTX_BASE = "https://otx.alienvault.com/api/v1"

class AlienVaultOTXClient:
    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key or ""

    def _get(self, path: str) -> Dict:
        try:
            req = urllib.request.Request(f"{OTX_BASE}{path}", headers={"X-OTX-API-KEY": self.api_key})
            with urllib.request.urlopen(req, timeout=8) as resp:  # nosec B310
                return json.loads(resp.read())
        except Exception as e:
            return {"error": str(e)}

    def lookup_ip(self, ip: str) -> Dict:
        return self._get(f"/indicators/IPv4/{ip}/general")

    def lookup_domain(self, domain: str) -> Dict:
        return self._get(f"/indicators/domain/{domain}/general")

    def lookup_hash(self, file_hash: str) -> Dict:
        return self._get(f"/indicators/file/{file_hash}/general")
