"""Asset Pydantic schemas."""
from pydantic import BaseModel
from datetime import datetime
from typing import List


class AssetResponse(BaseModel):
    id: int
    subdomain: str
    is_alive: bool
    scan_run_id: int
    priority: int
    first_seen: datetime
    model_config = {"from_attributes": True}


class AssetListResponse(BaseModel):
    total: int
    page: int
    per_page: int
    items: List[AssetResponse]
