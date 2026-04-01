"""Scan state management for Technieum Enterprise."""
from typing import Any, Dict, Optional
from datetime import datetime
import json, logging
from pathlib import Path

logger = logging.getLogger(__name__)

class StateManager:
    """Track scan state with optional file-backed persistence."""

    def __init__(self, state_dir: str = ".technieum_state") -> None:
        self._dir = Path(state_dir)
        self._dir.mkdir(exist_ok=True)
        self._state: Dict[str, Dict] = {}

    def _path(self, scan_id: int) -> Path:
        return self._dir / f"scan_{scan_id}.json"

    def set_state(self, scan_id: int, key: str, value: Any) -> None:
        if scan_id not in self._state:
            self._state[scan_id] = {}
        self._state[scan_id][key] = value
        self._state[scan_id]["updated_at"] = datetime.utcnow().isoformat()
        self._persist(scan_id)

    def get_state(self, scan_id: int, key: str, default: Any = None) -> Any:
        self._load(scan_id)
        return self._state.get(scan_id, {}).get(key, default)

    def get_all(self, scan_id: int) -> Dict:
        self._load(scan_id)
        return self._state.get(scan_id, {})

    def _persist(self, scan_id: int) -> None:
        try:
            self._path(scan_id).write_text(json.dumps(self._state.get(scan_id, {}), default=str))
        except Exception as e:
            logger.warning(f"State persist failed for scan {scan_id}: {e}")

    def _load(self, scan_id: int) -> None:
        if scan_id not in self._state and self._path(scan_id).exists():
            try:
                self._state[scan_id] = json.loads(self._path(scan_id).read_text())
            except Exception:
                self._state[scan_id] = {}

    def clear(self, scan_id: int) -> None:
        self._state.pop(scan_id, None)
        p = self._path(scan_id)
        if p.exists():
            p.unlink()
