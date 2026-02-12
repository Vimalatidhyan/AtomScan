from pydantic import BaseModel
from typing import Optional


class Finding(BaseModel):
    id: Optional[int] = None
    target: str
    host: str
    tool: str
    severity: str
    name: str
    info: Optional[str] = None
    cve: Optional[str] = None


class FindingSummary(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
