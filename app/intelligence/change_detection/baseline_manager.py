"""Baseline snapshot manager for change detection."""
from typing import Dict
import json
import hashlib
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class BaselineManager:
    """Manage scan baselines for drift analysis."""

    def __init__(self, scan_run_id: int) -> None:
        self.scan_run_id = scan_run_id

    def _serialize_scan(self, scan_data: Dict) -> str:
        return json.dumps(scan_data, sort_keys=True, default=str)

    def create_baseline(self, scan_data: Dict) -> Dict:
        """Create a new baseline snapshot from scan data."""
        serialized = self._serialize_scan(scan_data)
        md5 = hashlib.md5(serialized.encode()).hexdigest()  # nosec B324
        snapshot = {
            "scan_run_id": self.scan_run_id,
            "snapshot_date": datetime.utcnow().isoformat(),
            "is_baseline": True,
            "subdomain_count": len(scan_data.get("subdomains", [])),
            "vulnerability_count": len(scan_data.get("vulnerabilities", [])),
            "md5_hash": md5,
            "snapshot_data": serialized,
        }
        logger.info(f"Created baseline for scan {self.scan_run_id}: {md5}")
        return snapshot

    def compare_to_baseline(self, baseline_data: Dict, current_data: Dict) -> Dict:
        """Compare current scan to baseline. Returns delta."""
        from app.intelligence.change_detection.calculate_delta import calculate_delta
        return calculate_delta(baseline_data, current_data)
