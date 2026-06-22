"""Read endpoints: snapshot, single host, status, and scan trigger."""

from __future__ import annotations

import asyncio
import ipaddress

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import require_operator
from ..config import settings
from ..db import fetch_host, fetch_host_by_ip, fetch_hosts, get_session
from ..models import Host
from ..scanner.netdetect import get_public_ip
from ..scanner.runner import nmap_available
from ..serialize import host_to_dict, hosts_to_list
from ..ws import manager

router = APIRouter()


class AddHostBody(BaseModel):
    ip: str


class DeleteHostsBody(BaseModel):
    ids: list[int]


@router.get("/hosts")
async def list_hosts(session: AsyncSession = Depends(get_session)) -> dict:
    hosts = await fetch_hosts(session)
    return {"rev": manager.rev, "hosts": hosts_to_list(hosts)}


@router.get("/hosts/{host_id}")
async def get_host(host_id: int, session: AsyncSession = Depends(get_session)) -> dict:
    host = await fetch_host(session, host_id)
    if host is None:
        raise HTTPException(status_code=404, detail="host not found")
    return host_to_dict(host)


@router.get("/status")
async def status() -> dict:
    return {
        "mode": settings.mode,
        "nmap_available": nmap_available(),
        "target_cidr": settings.effective_cidr or settings.target_cidr,
        "target_cidr_config": settings.target_cidr,
        "scan_interval_min": settings.scan_interval_min,
        "ws_clients": manager.count,
        "rev": manager.rev,
        "event": settings.event_name,
        "organizer": settings.organizer,
        # Public/WAN IP for the central node ("Private closed network" if none).
        # Egress-free in mock mode; never blocks (cached, probed off the loop).
        "public_ip": await get_public_ip(settings.public_ip_lookup and not settings.is_mock),
    }


@router.post("/scan/now", dependencies=[Depends(require_operator)])
async def scan_now() -> dict:
    # imported here to avoid a circular import at module load
    from ..scan_cycle import scan_cycle

    asyncio.create_task(scan_cycle())
    return {"started": True}


@router.post("/hosts", dependencies=[Depends(require_operator)])
async def add_host(body: AddHostBody, session: AsyncSession = Depends(get_session)) -> dict:
    """Manually add a device by IP — for undetected hosts or ones outside the scan
    CIDR (e.g. a dedicated server with a public IP). It appears immediately and is
    included as a target on the next scan."""
    ip = body.ip.strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"invalid IP address: {ip!r}")
    if addr.version != 4:
        raise HTTPException(
            status_code=400,
            detail="IPv6 targets aren't supported yet — please use an IPv4 address.",
        )

    existing = await fetch_host_by_ip(session, ip)
    if existing is not None:
        return host_to_dict(existing)

    # ports=[] keeps the relationship "loaded" so serialization never lazy-loads.
    host = Host(ip=ip, manual=True, ports=[])
    session.add(host)
    await session.commit()
    await manager.broadcast()

    # Fingerprinting happens in real mode only (mock regenerates a fixed LAN);
    # the new host is now a permanent scan target either way.
    if not settings.is_mock:
        from ..scan_cycle import scan_cycle
        asyncio.create_task(scan_cycle())
    return host_to_dict(host)


@router.post("/hosts/delete", dependencies=[Depends(require_operator)])
async def delete_hosts(body: DeleteHostsBody, session: AsyncSession = Depends(get_session)) -> dict:
    """Remove hosts from the diagram (cascades to their ports/CVEs). Auto-detected
    devices reappear on the next scan; manual ones stay gone until re-added."""
    deleted = 0
    for hid in body.ids:
        host = await fetch_host(session, hid)
        if host is not None:
            await session.delete(host)  # ORM cascade removes ports + cves
            deleted += 1
    if deleted:
        await session.commit()
        await manager.broadcast()
    return {"deleted": deleted}
