"""Abuse.ch API clients (URLhaus, MalwareBazaar, ThreatFox)."""
from typing import Dict
import logging
import urllib.request
import json
import urllib.parse

logger = logging.getLogger(__name__)

class AbuseChClient:
    URLHAUS = "https://urlhaus-api.abuse.ch/v1/"
    THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"

    def lookup_url(self, url: str) -> Dict:
        """Look up a URL in URLhaus."""
        try:
            data = urllib.parse.urlencode({"url": url}).encode()
            req = urllib.request.Request(self.URLHAUS + "url/", data=data, method="POST")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read())
        except Exception as e:
            return {"url": url, "query_status": "error", "error": str(e)}

    def lookup_ioc(self, ioc: str, ioc_type: str = "domain") -> Dict:
        """Look up an IOC in ThreatFox."""
        try:
            payload = json.dumps({"query": "search_ioc", "search_term": ioc}).encode()
            req = urllib.request.Request(self.THREATFOX, data=payload, method="POST", headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read())
        except Exception as e:
            return {"ioc": ioc, "query_status": "error", "error": str(e)}
