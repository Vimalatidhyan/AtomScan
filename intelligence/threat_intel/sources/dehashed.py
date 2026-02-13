"""DeHashed API client for leaked credential lookup."""
from typing import Dict, Optional
import logging, urllib.request, urllib.parse, json, base64

logger = logging.getLogger(__name__)
DEHASHED_URL = "https://api.dehashed.com/search"

class DeHashedClient:
    def __init__(self, email: Optional[str] = None, api_key: Optional[str] = None) -> None:
        self.email = email or ""
        self.api_key = api_key or ""

    def _auth(self) -> str:
        creds = f"{self.email}:{self.api_key}"
        return base64.b64encode(creds.encode()).decode()

    def search(self, query: str, size: int = 20) -> Dict:
        """Search DeHashed for leaked credentials."""
        try:
            url = f"{DEHASHED_URL}?query={urllib.parse.quote(query)}&size={size}"
            req = urllib.request.Request(url, headers={"Authorization": f"Basic {self._auth()}", "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read())
        except Exception as e:
            return {"query": query, "total": 0, "entries": [], "error": str(e)}
