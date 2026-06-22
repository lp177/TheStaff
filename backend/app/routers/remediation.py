"""Write endpoints: CVE/port detail, accept/reopen, and the healthcheck re-test."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import require_operator
from ..db import fetch_cve, fetch_port, get_session
from ..models import CVE, Host, Port, State, utcnow
from ..scanner.healthcheck import command_templates, healthcheck_cve, healthcheck_port
from ..serialize import cve_to_dict, port_to_dict
from ..ws import manager

router = APIRouter()


class AcceptBody(BaseModel):
    note: str | None = None
    acknowledged_by: str | None = None


def _advice(category: str | None, product: str | None, fixed_version: str | None) -> list[str]:
    tips: list[str] = []
    if fixed_version and product:
        tips.append(f"Update {product} to version {fixed_version} or later.")
    by_cat = {
        "smb": [
            "Disable SMBv1 and apply the latest OS security updates.",
            "Block TCP/445 and 139 at the firewall if file sharing isn't needed.",
        ],
        "http": [
            "Update the web service / device firmware to the latest release.",
            "Restrict the admin interface to the LAN/VPN and require authentication.",
        ],
        "tls": [
            "Disable SSLv3/TLS 1.0/1.1 and weak ciphers; require TLS 1.2+.",
            "Renew the certificate and prefer short-lived, properly-signed certs.",
        ],
        "version": [
            "Upgrade the software to a patched version.",
            "If the version is end-of-life, replace it with a supported alternative.",
        ],
        "creds": [
            "Change any default/weak credentials immediately.",
            "Disable plaintext protocols (telnet/FTP); use SSH/SFTP instead.",
        ],
        "openport": [
            "Close the port if the service isn't needed.",
            "Otherwise restrict it with a firewall rule to trusted hosts only.",
        ],
        "dos": [
            "Apply the vendor patch that addresses the resource-exhaustion issue.",
            "Rate-limit or firewall the service if a patch isn't available yet.",
        ],
        "injection": [
            "Apply the vendor patch and keep the software updated.",
            "Restrict network exposure of the affected endpoint.",
        ],
    }
    tips.extend(by_cat.get(category or "version", by_cat["version"]))
    tips.append("If you can't fix it now, you can knowingly Accept this finding (turns it blue).")
    return tips


@router.get("/cves/{cve_id}")
async def cve_detail(cve_id: int, session: AsyncSession = Depends(get_session)) -> dict:
    cve = await fetch_cve(session, cve_id)
    if cve is None:
        raise HTTPException(status_code=404, detail="cve not found")
    port = cve.port
    ip = port.host.ip if port and port.host else None
    data = cve_to_dict(cve)
    data["host_ip"] = ip
    data["host_id"] = port.host_id if port else None
    data["port"] = {"id": port.id, "number": port.number, "protocol": port.protocol,
                    "service": port.service, "product": port.product,
                    "version": port.version, "cpe": port.cpe} if port else None
    data["test_commands"] = command_templates(
        ip or "<host>",
        port.number if port else 0,
        cve.category,
        protocol=port.protocol if port else "tcp",
        service=port.service if port else None,
        product=port.product if port else None,
        version=port.version if port else None,
        cve_id=cve.cve_id,
        fixed_version=cve.fixed_version,
    )
    data["remediation"] = _advice(cve.category, port.product if port else None, cve.fixed_version)
    return data


@router.post("/cves/{cve_id}/accept", dependencies=[Depends(require_operator)])
async def accept_cve(cve_id: int, body: AcceptBody | None = None,
                     session: AsyncSession = Depends(get_session)) -> dict:
    cve = await fetch_cve(session, cve_id)
    if cve is None:
        raise HTTPException(status_code=404, detail="cve not found")
    cve.state = State.accepted
    cve.updated_at = utcnow()
    await session.commit()
    await manager.broadcast()
    return {"ok": True, "cve": cve_to_dict(cve)}


@router.post("/cves/{cve_id}/reopen", dependencies=[Depends(require_operator)])
async def reopen_cve(cve_id: int, session: AsyncSession = Depends(get_session)) -> dict:
    cve = await fetch_cve(session, cve_id)
    if cve is None:
        raise HTTPException(status_code=404, detail="cve not found")
    cve.state = State.open
    cve.updated_at = utcnow()
    await session.commit()
    await manager.broadcast()
    return {"ok": True, "cve": cve_to_dict(cve)}


@router.post("/cves/{cve_id}/healthcheck", dependencies=[Depends(require_operator)])
async def run_cve_healthcheck(cve_id: int, session: AsyncSession = Depends(get_session)) -> dict:
    cve = await fetch_cve(session, cve_id)
    if cve is None:
        raise HTTPException(status_code=404, detail="cve not found")
    ip = cve.port.host.ip if cve.port and cve.port.host else "<host>"
    outcome = await healthcheck_cve(session, cve, ip)
    await manager.broadcast()
    return outcome


@router.post("/ports/{port_id}/accept", dependencies=[Depends(require_operator)])
async def accept_port(port_id: int, body: AcceptBody | None = None,
                      session: AsyncSession = Depends(get_session)) -> dict:
    port = await fetch_port(session, port_id)
    if port is None:
        raise HTTPException(status_code=404, detail="port not found")
    port.state = State.accepted
    port.updated_at = utcnow()
    await session.commit()
    await manager.broadcast()
    return {"ok": True, "port": port_to_dict(port)}


@router.post("/ports/{port_id}/reopen", dependencies=[Depends(require_operator)])
async def reopen_port(port_id: int, session: AsyncSession = Depends(get_session)) -> dict:
    port = await fetch_port(session, port_id)
    if port is None:
        raise HTTPException(status_code=404, detail="port not found")
    port.state = State.open
    port.updated_at = utcnow()
    await session.commit()
    await manager.broadcast()
    return {"ok": True, "port": port_to_dict(port)}


@router.post("/ports/{port_id}/healthcheck", dependencies=[Depends(require_operator)])
async def run_port_healthcheck(port_id: int, session: AsyncSession = Depends(get_session)) -> dict:
    port = await fetch_port(session, port_id)
    if port is None:
        raise HTTPException(status_code=404, detail="port not found")
    ip = port.host.ip if port.host else "<host>"
    outcome = await healthcheck_port(session, port, ip)
    await manager.broadcast()
    return outcome


@router.post("/wipe", dependencies=[Depends(require_operator)])
async def wipe(session: AsyncSession = Depends(get_session)) -> dict:
    """Delete all collected data (run at the end of an event)."""
    await session.execute(delete(CVE))
    await session.execute(delete(Port))
    await session.execute(delete(Host))
    await session.commit()
    await manager.broadcast()
    return {"ok": True}
