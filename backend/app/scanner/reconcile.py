"""Reconcile a freshly parsed scan into the DB, applying the state machine.

Rules:
  - Upsert by natural key: host.ip, (host, number, protocol), (port, cve_id).
  - Present this cycle           -> last_seen = now. solved -> open (regression).
  - In a *scanned* host, absent  -> open -> solved. accepted is never touched.
  - A host not seen at all this cycle (guest left) is left untouched — we can't
    conclude "solved" from an offline device.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlmodel import select

from ..models import CVE, Host, Port, State, utcnow
from .types import ParsedHost, ParsedPort

log = logging.getLogger("thestaff.reconcile")


async def reconcile(session: AsyncSession, parsed: list[ParsedHost]) -> dict:
    stats = {"new_hosts": 0, "new_findings": 0, "resolved": 0, "regressed": 0}
    now = utcnow()

    for ph in parsed:
        result = await session.execute(
            select(Host)
            .where(Host.ip == ph.ip)
            .options(selectinload(Host.ports).selectinload(Port.cves))
        )
        host = result.scalars().first()
        if host is None:
            # ports=[] marks the collection "loaded" so later access never
            # triggers a lazy SELECT (which would fail in async / no-greenlet).
            host = Host(ip=ph.ip, first_seen=now, ports=[])
            session.add(host)
            stats["new_hosts"] += 1

        host.mac = ph.mac or host.mac
        host.vendor = ph.vendor or host.vendor
        host.hostname = ph.hostname or host.hostname
        host.device_type = ph.device_type or host.device_type
        host.os_family = ph.osfamily or host.os_family
        if ph.osaccuracy:
            host.os_accuracy = ph.osaccuracy
        host.last_seen = now
        host.updated_at = now
        await session.flush()

        existing_ports = {(p.number, p.protocol): p for p in host.ports}
        scanned_keys = set()

        for pp in ph.ports:
            key = (pp.number, pp.protocol)
            scanned_keys.add(key)
            port = existing_ports.get(key)
            if port is None:
                port = Port(
                    host_id=host.id, number=pp.number, protocol=pp.protocol,
                    first_seen=now, cves=[],
                )
                session.add(port)
                host.ports.append(port)
                stats["new_findings"] += 1
            port.service = pp.service or port.service
            port.product = pp.product or port.product
            port.version = pp.version or port.version
            port.cpe = pp.cpe or port.cpe
            port.last_seen = now
            port.updated_at = now
            if port.state == State.solved:  # port reappeared -> regression
                port.state = State.open
                stats["regressed"] += 1
            await session.flush()

            _reconcile_cves(session, port, pp, now, stats)

        # Ports of a scanned host that vanished this cycle -> solved.
        for key, port in existing_ports.items():
            if key in scanned_keys:
                continue
            if port.state == State.open:
                port.state = State.solved
                port.updated_at = now
                stats["resolved"] += 1
            for cve in port.cves:
                if cve.state == State.open:
                    cve.state = State.solved
                    cve.updated_at = now
                    stats["resolved"] += 1

        host.state = _rollup_state(host)

    await session.commit()
    if any(stats.values()):
        log.info("reconcile: %s", stats)
    return stats


def _reconcile_cves(
    session: AsyncSession, port: Port, pp: ParsedPort, now: datetime, stats: dict
) -> None:
    existing = {c.cve_id.upper(): c for c in port.cves}
    scanned_ids = set()
    for pc in pp.cves:
        cid = pc.cve_id.upper()
        scanned_ids.add(cid)
        cve = existing.get(cid)
        if cve is None:
            cve = CVE(port_id=port.id, cve_id=cid, first_seen=now)
            session.add(cve)
            port.cves.append(cve)
            stats["new_findings"] += 1
        cve.cvss = pc.cvss if pc.cvss is not None else cve.cvss
        cve.summary = pc.summary or cve.summary
        cve.references = json.dumps(pc.references) if pc.references else cve.references
        cve.is_exploit = pc.is_exploit or cve.is_exploit
        cve.category = pc.category or cve.category
        cve.fixed_version = pc.fixed_version or cve.fixed_version
        cve.source = pc.source or cve.source
        cve.last_seen = now
        cve.updated_at = now
        if cve.state == State.solved:  # re-detected -> regression
            cve.state = State.open
            stats["regressed"] += 1

    for cid, cve in existing.items():
        if cid not in scanned_ids and cve.state == State.open:
            cve.state = State.solved
            cve.updated_at = now
            stats["resolved"] += 1


def _rollup_state(host: Host) -> State:
    has_open = any(p.state == State.open for p in host.ports) or any(
        c.state == State.open for p in host.ports for c in p.cves
    )
    if has_open:
        return State.open
    has_accepted = any(p.state == State.accepted for p in host.ports) or any(
        c.state == State.accepted for p in host.ports for c in p.cves
    )
    return State.accepted if has_accepted else State.solved
