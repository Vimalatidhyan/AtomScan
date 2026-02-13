"""Scan Pydantic schemas with enhanced validation."""
from pydantic import BaseModel, Field, validator, field_validator
from datetime import datetime
from typing import Optional, List
import re

class ScanCreateRequest(BaseModel):
    domain: str = Field(
        ...,
        min_length=3,
        max_length=255,
        description="Target domain (e.g., example.com)",
        pattern=r'^[a-zA-Z0-9][a-zA-Z0-9-_.]*[a-zA-Z0-9]$'
    )
    scan_type: str = Field(
        default="full",
        pattern=r'^(full|quick|deep|custom)$',
        description="Scan type: full, quick, deep, or custom"
    )
    custom_phases: Optional[List[int]] = Field(
        default=None,
        description="Custom phase selection (0-4)"
    )
    
    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        """Validate domain format and remove dangerous characters."""
        v = v.lower().strip()
        
        # Reject IP addresses (should use IP scanning endpoint)
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, v):
            raise ValueError('Use IP scanning endpoint for IP addresses')
        
        # Reject localhost and internal domains
        if v in ['localhost', '127.0.0.1', '0.0.0.0'] or v.endswith('.local'):
            raise ValueError('Cannot scan localhost or internal domains')
        
        # Basic domain validation
        domain_pattern = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
        if not re.match(domain_pattern, v):
            raise ValueError('Invalid domain format')
        
        return v
    
    @field_validator('custom_phases')
    @classmethod
    def validate_custom_phases(cls, v: Optional[List[int]]) -> Optional[List[int]]:
        """Validate custom phases are in valid range."""
        if v is not None:
            if not v:
                raise ValueError('custom_phases must not be empty if provided')
            if not all(0 <= p <= 4 for p in v):
                raise ValueError('Phase numbers must be between 0-4')
            if len(v) != len(set(v)):
                raise ValueError('Duplicate phases not allowed')
            return sorted(v)
        return v
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "domain": "example.com",
                "scan_type": "full",
                "custom_phases": [0, 1, 2]
            }
        }
    }

class ScanUpdateRequest(BaseModel):
    status: Optional[str] = Field(
        default=None,
        pattern=r'^(running|paused|stopped|completed|failed)$',
        description="Scan status"
    )
    scan_type: Optional[str] = Field(
        default=None,
        pattern=r'^(full|quick|deep|custom)$'
    )

class ScanResponse(BaseModel):
    id: int
    domain: str
    scan_type: str
    status: str
    risk_score: Optional[int] = None
    phase: int
    created_at: datetime
    completed_at: Optional[datetime] = None
    model_config = {"from_attributes": True}

class ScanListResponse(BaseModel):
    total: int
    page: int
    per_page: int
    items: List[ScanResponse]
