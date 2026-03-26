"""Finding Pydantic schemas with enhanced validation."""
from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import Optional, List

class FindingResponse(BaseModel):
    id: int
    scan_run_id: Optional[int] = None
    vuln_type: Optional[str] = None
    severity: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    remediation: Optional[str] = None
    discovered_at: Optional[datetime] = None
    model_config = {"from_attributes": True}

class FindingListResponse(BaseModel):
    total: int
    page: int
    per_page: int
    items: List[FindingResponse]

class FindingUpdateRequest(BaseModel):
    severity: Optional[str] = Field(
        default=None,
        description="Severity level (critical, high, medium, low, info)"
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
