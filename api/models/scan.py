from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime


class ScanCreate(BaseModel):
    target: str
    phases: Optional[List[int]] = None  # default [1,2,3,4]


class ScanStatus(BaseModel):
    scan_id: str
    target: str
    status: str  # pending, running, completed, failed
    progress: int  # 0-100
    current_phase: Optional[int] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None


class ScanListItem(BaseModel):
    scan_id: str
    target: str
    status: str
    progress: int
    started_at: Optional[str] = None
