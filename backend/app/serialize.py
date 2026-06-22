"""Serialization contract shared by REST, WebSocket, and the Vue frontend.

A "snapshot" is ``{type, rev, hosts: [HostDict]}``. HostDict shape:

    {
      id, ip, mac, vendor, hostname, device_type, os_family,
      state, worst_state, first_seen, last_seen,
      counts: {open, solved, accepted, cve_open},
      ports: [{
        id, number, protocol, service, product, version, cpe, state,
        cves: [{id, cve_id, cvss, summary, references[], is_exploit,
                category, fixed_version, source, state}]
      }]
    }

``worst_state`` rolls children up for node coloring:
    any open -> "open" (red); else any accepted -> "accepted" (blue);
    else "solved" (green); empty host with no findings -> "clean".
"""

from __future__ import annotations

import json
from datetime import datetime

from .models import CVE, Host, Port, State

_STATE_RANK = {State.open: 3, State.accepted: 2, State.solved: 1}


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _refs(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        val = json.loads(raw)
        return val if isinstance(val, list) else []
    except (ValueError, TypeError):
        return []


def cve_to_dict(cve: CVE) -> dict:
    return {
        "id": cve.id,
        "cve_id": cve.cve_id,
        "cvss": cve.cvss,
        "severity": severity_band(cve.cvss),
        "summary": cve.summary,
        "references": _refs(cve.references),
        "is_exploit": cve.is_exploit,
        "category": cve.category,
        "fixed_version": cve.fixed_version,
        "source": cve.source,
        "state": cve.state.value,
        "first_seen": _iso(cve.first_seen),
        "last_seen": _iso(cve.last_seen),
    }


def port_to_dict(port: Port) -> dict:
    return {
        "id": port.id,
        "number": port.number,
        "protocol": port.protocol,
        "service": port.service,
        "product": port.product,
        "version": port.version,
        "cpe": port.cpe,
        "state": port.state.value,
        "cves": [cve_to_dict(c) for c in sorted(
            port.cves, key=lambda c: (-(c.cvss or 0.0), c.cve_id)
        )],
    }


def severity_band(cvss: float | None) -> str:
    if cvss is None:
        return "unknown"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0.0:
        return "low"
    return "none"


def worst_state(host: Host) -> str:
    """Roll up the host's ports + cves into a single coloring state."""
    rank = 0
    has_finding = False
    for port in host.ports:
        has_finding = True
        rank = max(rank, _STATE_RANK[port.state])
        for cve in port.cves:
            rank = max(rank, _STATE_RANK[cve.state])
    if not has_finding:
        return "clean"
    for state, value in _STATE_RANK.items():
        if value == rank:
            return state.value
    return "solved"


def host_counts(host: Host) -> dict:
    counts = {"open": 0, "solved": 0, "accepted": 0, "cve_open": 0}
    for port in host.ports:
        counts[port.state.value] += 1
        for cve in port.cves:
            counts[cve.state.value] += 1
            if cve.state == State.open:
                counts["cve_open"] += 1
    return counts


def host_to_dict(host: Host) -> dict:
    return {
        "id": host.id,
        "ip": host.ip,
        "mac": host.mac,
        "vendor": host.vendor,
        "hostname": host.hostname,
        "device_type": host.device_type or "unknown",
        "os_family": host.os_family,
        "os_accuracy": host.os_accuracy,
        "manual": host.manual,
        "state": host.state.value,
        "worst_state": worst_state(host),
        "counts": host_counts(host),
        "first_seen": _iso(host.first_seen),
        "last_seen": _iso(host.last_seen),
        "ports": [port_to_dict(p) for p in sorted(host.ports, key=lambda p: p.number)],
    }


def hosts_to_list(hosts: list[Host]) -> list[dict]:
    return [host_to_dict(h) for h in hosts]
