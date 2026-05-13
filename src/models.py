from pydantic import BaseModel, Field
from typing import List, Optional, Set
from enum import Enum
import uuid


class TargetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"


class Service(BaseModel):
    port: int
    protocol: str = "tcp"
    name: str
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None


class Vulnerability(BaseModel):
    id: str
    name: str
    severity: str
    description: Optional[str] = None
    extracted_results: List[str] = Field(default_factory=list)


class Target(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    raw_input: str
    type: TargetType
    address: str
    resolved_ips: Set[str] = Field(default_factory=set)
    services: List[Service] = Field(default_factory=list)
    technologies: Set[str] = Field(default_factory=set)
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    tags: Set[str] = Field(default_factory=set)
    parent_domain: Optional[str] = None
    error_log: List[str] = Field(default_factory=list)
    is_dead: bool = False

    class Config:
        use_enum_values = True