"""GreyNoise Community API client."""
from typing import Dict, Optional
import logging
import urllib.request
import json

logger = logging.getLogger(__name__)
GREYNOISE_URL = "https://api.greynoise.io/v3/community/{ip}"

class GreyNoiseClient:
    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key or ""

    def lookup_ip(self, ip: str) -> Dict:
        """Check GreyNoise community API for an IP."""
        try:
            req = urllib.request.Request(
                GREYNOISE_URL.format(ip=ip),
                headers={"key": self.api_key} if self.api_key else {},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read())
        except Exception as e:
            logger.debug(f"GreyNoise lookup failed for {ip}: {e}")
            return {"ip": ip, "noise": False, "riot": False, "classification": "unknown", "error": str(e)}
