"""Finding Pydantic schemas with enhanced validation."""
from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import Optional, List

class FindingResponse(BaseModel):
    id: int
    scan_run_id: int
    vuln_type: str
    severity: Optional[int] = None
    title: str
    description: Optional[str] = None
    remediation: Optional[str] = None
    discovered_at: datetime
    model_config = {"from_attributes": True}

class FindingListResponse(BaseModel):
    total: int
    page: int
    per_page: int
    items: List[FindingResponse]

class FindingUpdateRequest(BaseModel):
    severity: Optional[int] = Field(
        default=None,
        ge=0,
        le=100,
        description="Severity score (0-100)"
    )
    remediation: Optional[str] = Field(
        default=None,
        max_length=10000,
        description="Remediation instructions"
    )
    status: Optional[str] = Field(
        default=None,
        pattern=r'^(open|confirmed|resolved|false_positive|wont_fix)$',
        description="Finding status"
    )
    
    @field_validator('remediation')
    @classmethod
    def validate_remediation(cls, v: Optional[str]) -> Optional[str]:
        """Sanitize remediation text."""
        if v is not None:
            v = v.strip()
            if len(v) == 0:
                return None
        return v
