"""Threat intel Pydantic schemas."""
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class ThreatIntelResponse(BaseModel):
    id: int
    indicator_type: str
    indicator_value: str
    severity: Optional[int] = None
    source: str
    last_updated: Optional[datetime] = None
    model_config = {"from_attributes": True}
