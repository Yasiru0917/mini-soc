"""Scan, device and scope shapes."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=64, description="IP address or CIDR, e.g. 192.168.56.0/24")
    profile: Literal["discovery", "quick", "service"]


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target: str
    profile: str
    status: str
    command: str | None
    requested_by: str | None = None
    hosts_up: int | None
    open_ports: int | None
    alerts_raised: int
    error: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class PortOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    port: int
    protocol: str
    state: str
    service: str | None
    product: str | None
    version: str | None
    last_seen: datetime


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip: str
    hostname: str | None
    mac: str | None
    vendor: str | None
    state: str
    first_seen: datetime
    last_seen: datetime
    last_scan_id: int | None
    ports: list[PortOut] = []


class ProfileOut(BaseModel):
    id: str
    label: str
    command: str
    description: str


class ScopeOut(BaseModel):
    cidrs: list[str]
    is_default: bool
    updated_at: datetime | None = None
    updated_by: str | None = None


class ScopeUpdate(BaseModel):
    cidrs: list[str] = Field(min_length=1, max_length=20)
    allow_public: bool = False
