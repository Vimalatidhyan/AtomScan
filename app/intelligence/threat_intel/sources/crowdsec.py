"""CrowdSec CTI API client."""
from typing import Dict, Optional
import logging
import urllib.request
import json

logger = logging.getLogger(__name__)
CROWDSEC_URL = "https://cti.api.crowdsec.net/v2/smoke/{ip}"

class CrowdSecClient:
    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key or ""

    def lookup_ip(self, ip: str) -> Dict:
        """Query CrowdSec CTI for an IP address."""
        try:
            req = urllib.request.Request(
                CROWDSEC_URL.format(ip=ip),
                headers={"x-api-key": self.api_key},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310
                return json.loads(resp.read())
        except Exception as e:
            return {"ip": ip, "error": str(e), "behaviors": []}
