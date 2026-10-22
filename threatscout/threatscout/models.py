from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field

_HASH = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_DOMAIN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CLEAN = "CLEAN"


class ProviderResult(BaseModel):
    provider: str
    success: bool = True
    cached: bool = False
    error: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)
    normalized: dict[str, Any] = Field(default_factory=dict)


class RiskBreakdown(BaseModel):
    virustotal: float = 0.0
    abuseipdb: float = 0.0
    shodan: float = 0.0
    otx: float = 0.0
    greynoise: float = 0.0
    urlhaus: float = 0.0
    misp: float = 0.0
    weights_applied: dict[str, float] = Field(default_factory=dict)


class EnrichmentReport(BaseModel):
    id: int | None = None
    ioc: str
    ioc_type: IOCType
    threat_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.CLEAN
    risk_breakdown: RiskBreakdown = Field(default_factory=RiskBreakdown)
    providers: list[ProviderResult] = Field(default_factory=list)
    geo: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    related: dict[str, list[str]] = Field(default_factory=dict)
    cves: list[dict[str, Any]] = Field(default_factory=list)
    whois: dict[str, Any] = Field(default_factory=dict)
    cached: bool = False
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        data = self.model_dump(mode="json")
        data["ioc_type"] = self.ioc_type.value
        data["risk_level"] = self.risk_level.value
        return data


def detect_ioc_type(value: str) -> IOCType:
    value = value.strip()
    if _EMAIL.match(value):
        return IOCType.EMAIL
    if _HASH.match(value):
        return IOCType.HASH
    try:
        ipaddress.ip_address(value)
        return IOCType.IP
    except ValueError:
        pass
    if value.startswith(("http://", "https://")):
        return IOCType.URL
    host = urlparse(value if "://" in value else f"http://{value}").hostname or value
    if _DOMAIN.match(host):
        return IOCType.DOMAIN
    return IOCType.UNKNOWN


def cache_key(ioc: str, provider: str) -> str:
    return hashlib.sha256(f"{provider}:{ioc.strip().lower()}".encode()).hexdigest()
