"""Scan scheduler using APScheduler (or simple threading fallback)."""
from typing import Callable, Dict
import logging
import threading
import time
from datetime import datetime

logger = logging.getLogger(__name__)

class ScanScheduler:
    """Schedule and manage recurring scan jobs."""

    def __init__(self) -> None:
        self._jobs: Dict[str, Dict] = {}
        self._threads: Dict[str, threading.Thread] = {}
        self._running = False

    def add_job(self, job_id: str, func: Callable, interval_hours: float = 24.0, args: tuple = ()) -> None:
        """Add a recurring job."""
        self._jobs[job_id] = {
            "func": func,
            "interval_seconds": interval_hours * 3600,
            "args": args,
            "last_run": None,
            "next_run": None,
            "active": True,
        }
        logger.info(f"Scheduled job {job_id} every {interval_hours}h")

    def start(self) -> None:
        """Start the scheduler loop in background thread."""
        self._running = True
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()

    def stop(self) -> None:
        """Stop the scheduler."""
        self._running = False

    def _loop(self) -> None:
        while self._running:
            now = datetime.utcnow()
            for job_id, job in self._jobs.items():
                if not job["active"]:
                    continue
                last = job["last_run"]
                interval = job["interval_seconds"]
                if last is None or (now - last).total_seconds() >= interval:
                    try:
                        logger.info(f"Running scheduled job: {job_id}")
                        job["func"](*job["args"])
                        job["last_run"] = now
                    except Exception as e:
                        logger.error(f"Scheduled job {job_id} failed: {e}")
            time.sleep(60)

    def remove_job(self, job_id: str) -> None:
        self._jobs.pop(job_id, None)

    def get_jobs(self) -> Dict:
        return {jid: {k: v for k, v in j.items() if k != "func"} for jid, j in self._jobs.items()}
