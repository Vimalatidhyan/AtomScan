from pydantic import BaseModel
from typing import Optional


class Subdomain(BaseModel):
    host: str
    ip: Optional[str] = None
    is_alive: bool = False
    status_code: Optional[int] = None
    source_tools: Optional[str] = None


class Port(BaseModel):
    host: str
    port: int
    protocol: str = "tcp"
    service: Optional[str] = None
    version: Optional[str] = None


class AssetSummary(BaseModel):
    subdomains: int
    alive_hosts: int
    urls: int
    open_ports: int
    leaks: int
    vulnerabilities: int
    critical_vulns: int
    high_vulns: int
