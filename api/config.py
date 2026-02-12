import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def get_db_path() -> str:
    return os.environ.get("RECONX_DB_PATH", str(ROOT / "reconx.db"))
