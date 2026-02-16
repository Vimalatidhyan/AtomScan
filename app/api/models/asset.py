"""Asset Pydantic schemas."""
from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List

class AssetResponse(BaseModel):
    id: int
    subdomain: str
    is_alive: Optional[bool] = False
    scan_run_id: Optional[int] = None
    priority: Optional[int] = 0
    first_seen: Optional[datetime] = None
    model_config = {"from_attributes": True}

class AssetListResponse(BaseModel):
    total: int
    page: int
    per_page: int
    items: List[AssetResponse]
