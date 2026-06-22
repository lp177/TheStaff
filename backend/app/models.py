"""SQLModel tables and the three-state remediation state machine.

State colors (mirrored in the Vue diagram):
    open     -> RED    : finding detected, not yet addressed
    solved   -> GREEN  : remediated / no longer present (scan or healthcheck verified)
    accepted -> BLUE   : operator + guest knowingly accept the risk (never auto-changed)

NOTE: deliberately no ``from __future__ import annotations`` here — SQLModel
resolves Relationship() types from the live annotations at class-definition time.
"""

import enum
from datetime import datetime, timezone

from sqlmodel import Field, Relationship, SQLModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class State(str, enum.Enum):
    open = "open"
    solved = "solved"
    accepted = "accepted"


class Host(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    ip: str = Field(index=True, unique=True)
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    device_type: str | None = Field(default=None, index=True)
    os_family: str | None = None
    os_accuracy: int = 0
    # Operator-added by IP (undetected device, or one outside the scan CIDR like a
    # dedicated server). Kept across scans and always included as a scan target.
    manual: bool = Field(default=False)
    # Host-level state is derived from its children at serialization time, but we
    # also persist a snapshot so list queries stay cheap.
    state: State = Field(default=State.open, index=True)
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    ports: list["Port"] = Relationship(
        back_populates="host",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )


class Port(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    host_id: int = Field(foreign_key="host.id", index=True)
    number: int = Field(index=True)
    protocol: str = Field(default="tcp")
    service: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: str | None = None
    state: State = Field(default=State.open, index=True)
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    host: Host = Relationship(back_populates="ports")
    cves: list["CVE"] = Relationship(
        back_populates="port",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )


class CVE(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    port_id: int = Field(foreign_key="port.id", index=True)
    cve_id: str = Field(index=True)
    cvss: float | None = None
    summary: str | None = None
    references: str | None = None  # JSON-encoded list[str]
    is_exploit: bool = Field(default=False)
    # Drives the healthcheck re-test strategy (tls/http/smb/version/openport/...).
    category: str | None = None
    # Optional "first fixed in" hint used by the Tier-2 version comparison.
    fixed_version: str | None = None
    source: str | None = None  # vulners | vulscan | mock
    state: State = Field(default=State.open, index=True)
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    port: Port = Relationship(back_populates="cves")


class HealthCheck(SQLModel, table=True):
    """Audit log: one row per re-test run, for transparency with guests."""

    id: int | None = Field(default=None, primary_key=True)
    target_kind: str  # "port" | "cve"
    target_id: int = Field(index=True)
    tier: int  # 1=reachability 2=identity 3=detection
    command: str
    raw_output: str
    result: str  # RESOLVED | LIKELY_RESOLVED | STILL_PRESENT | INCONCLUSIVE
    ran_at: datetime = Field(default_factory=utcnow)


class ConsentRecord(SQLModel, table=True):
    """Lightweight audit of opt-ins recorded from the consent page."""

    id: int | None = Field(default=None, primary_key=True)
    ip: str | None = None
    user_agent: str | None = None
    accepted: bool = True
    created_at: datetime = Field(default_factory=utcnow)
