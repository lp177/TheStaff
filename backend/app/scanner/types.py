"""Plain dataclasses that flow between scan stages.

These are the in-memory contract between the producers (real nmap parsing or the
mock generator) and the consumer (reconcile -> DB). Keeping them separate from
the SQLModel tables keeps parsing pure and easily testable.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ParsedCVE:
    cve_id: str
    cvss: float | None = None
    is_exploit: bool = False
    source: str | None = None  # vulners | vulscan | mock
    cpe: str | None = None
    # Filled by the enrichment stage:
    summary: str | None = None
    references: list[str] = field(default_factory=list)
    category: str | None = None
    fixed_version: str | None = None


@dataclass
class ParsedPort:
    number: int
    protocol: str = "tcp"
    service: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: str | None = None
    cves: list[ParsedCVE] = field(default_factory=list)


@dataclass
class ParsedHost:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostnames: list[str] = field(default_factory=list)
    devicetype: str | None = None  # raw nmap osclass type
    osfamily: str | None = None
    osaccuracy: int = 0
    mdns: list[str] = field(default_factory=list)  # mDNS service types if discovered
    ports: list[ParsedPort] = field(default_factory=list)
    # Resolved by the fingerprint stage:
    device_type: str | None = None

    @property
    def hostname(self) -> str | None:
        return self.hostnames[0] if self.hostnames else None
