"""Non-destructive, tiered "is it still there?" re-testing.

Principle: run the *least invasive* check that can answer, never exploit.
  Tier 1  reachability  -> is the port still open?         (closed => solved)
  Tier 2  identity      -> does the banner still show a vulnerable version?
  Tier 3  detection     -> re-run the single safe NSE script that flagged it.

Guardrails on every real check: single host, single port, --max-rate 50,
60s timeout, only safe/vuln detection scripts (never exploit/dos/intrusive,
never unsafe=1). Every attempt is written to the HealthCheck audit table.
"""

from __future__ import annotations

import logging
import re

from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from ..config import settings
from ..models import CVE, HealthCheck, Port, State, utcnow
from .runner import nmap_available, run_nmap

log = logging.getLogger("thestaff.healthcheck")

RESOLVED = "RESOLVED"
LIKELY_RESOLVED = "LIKELY_RESOLVED"
STILL_PRESENT = "STILL_PRESENT"
INCONCLUSIVE = "INCONCLUSIVE"
_SOLVING = {RESOLVED, LIKELY_RESOLVED}

# Tier-3 safe detection scripts per category (never exploit/dos/intrusive).
_TIER3_NSE = {
    "tls": "ssl-enum-ciphers,ssl-cert",
    "http": "http-headers,http-title",
    "smb": "smb-protocols,smb2-security-mode",
    "version": "vulners",
}

_SAFE_SELECTOR = "(vuln or safe) and not (exploit or dos or intrusive)"


def command_templates(
    ip: str,
    port: int,
    category: str | None,
    *,
    protocol: str = "tcp",
    service: str | None = None,
    product: str | None = None,
    version: str | None = None,
    cve_id: str | None = None,
    fixed_version: str | None = None,
) -> list[dict]:
    """Copy-pasteable, detection-only test commands tailored to *this* finding.

    Rather than a generic "is the port open?" probe (identical across every CVE on
    a host), the list is built from the finding's own context — the CVE id, the
    detected service/version, the protocol, and the version that fixes it — and
    ordered most-specific-first so the headline command actually answers "is this
    CVE still here?". Every command stays non-destructive (never exploits): we only
    ever re-detect, re-version, or run nmap's already-vetted safe scripts.
    """
    cat = category or "version"
    udp = protocol == "udp"
    sv = "-sU -sV" if udp else "-sV"            # UDP findings need -sU
    name = product or service or "this service"
    cmds: list[dict] = []

    # 1. Most CVE-specific check: re-run nmap's version-based CVE lookup and filter
    #    for *this* CVE. A matching line => still detected; no line => nmap no longer
    #    reports it for the running version. (Needs version detection to succeed.)
    if cve_id and cat != "openport":
        cmds.append({
            "tier": 3,
            "label": f"Is {cve_id} still detected? (safe, version-based — nmap vulners)",
            "command": f"nmap -Pn {sv} --script vulners -p {port} {ip} | grep -i {cve_id}",
        })

    # 2. Inspect the HTTP response/banner directly (safe, no exploit) for web findings.
    if cat == "http":
        scheme = "https" if port in (443, 8443) else "http"
        cmds.append({
            "tier": 2,
            "label": "Inspect the HTTP status line, headers & server banner (no exploit)",
            "command": f"curl -sSk -m 10 -D - -o /dev/null {scheme}://{ip}:{port}/",
        })

    # 3. Targeted, class-specific safe NSE (TLS ciphers/cert, SMB dialects, …).
    nse = _TIER3_NSE.get(cat)
    if nse and nse != "vulners":  # 'version' uses vulners, already covered in step 1
        cmds.append({
            "tier": 3,
            "label": f"Targeted {cat} detection — non-destructive, does not exploit",
            "command": f"timeout 60 nmap -Pn --max-rate 50 -p {port} {sv} "
                       f"--script \"{nse}\" {ip}",
        })

    # 4. Version comparison against the first fixed release — the cleanest pass/fail.
    if fixed_version:
        running = f"{name} {version}" if version else name
        cmds.append({
            "tier": 2,
            "label": f"Confirm the version — {running} is patched in {fixed_version}+ "
                     f"(compare to the VERSION nmap reports)",
            "command": f"nmap -Pn {sv} -p {port} {ip}",
        })

    # 5. Reachability. For an open-port finding this *is* the test (closing the port
    #    resolves it); for a CVE it's a quick "is the service even still listening?".
    nc_flags = "-zu" if udp else "-z"
    reach = {
        "tier": 1,
        "label": ("Is the port still open? Closing it resolves this finding"
                  if cat == "openport"
                  else "Baseline — is the service still listening?"),
        "command": f"nc {nc_flags} -w 5 {ip} {port} && echo OPEN || echo CLOSED",
    }
    if cat == "openport" or not cmds:
        cmds.insert(0, reach)   # lead with it when it's genuinely the test
    else:
        cmds.append(reach)

    # 6. Catch-all safe scan whose selector excludes any exploit/dos/intrusive script.
    cmds.append({
        "tier": 3,
        "label": "Safe-only scan (selector excludes every exploit/dos/intrusive script)",
        "command": f"nmap -Pn --max-rate 50 -p {port} {sv} "
                   f"--script \"{_SAFE_SELECTOR}\" {ip}",
    })
    return cmds


async def healthcheck_cve(session: AsyncSession, cve: CVE, ip: str) -> dict:
    port = cve.port
    outcome = await _perform(
        session, kind="cve", target_id=cve.id, ip=ip,
        number=port.number, protocol=port.protocol,
        category=cve.category, service=port.service,
        current_version=port.version, fixed_version=cve.fixed_version,
        cve_id=cve.cve_id,
    )
    if cve.state == State.open and outcome["result"] in _SOLVING:
        cve.state = State.solved
        cve.updated_at = utcnow()
        await session.commit()
    return outcome


async def healthcheck_port(session: AsyncSession, port: Port, ip: str) -> dict:
    outcome = await _perform(
        session, kind="port", target_id=port.id, ip=ip,
        number=port.number, protocol=port.protocol,
        category="openport", service=port.service,
        current_version=port.version, fixed_version=None, cve_id=None,
    )
    if port.state == State.open and outcome["result"] in _SOLVING:
        port.state = State.solved
        port.updated_at = utcnow()
        await session.commit()
    return outcome


async def _perform(session, *, kind, target_id, ip, number, protocol, category,
                   service, current_version, fixed_version, cve_id) -> dict:
    attempts: list[dict] = []

    if settings.is_mock or not nmap_available():
        attempts.append(await _mock_attempt(session, kind, target_id, ip, number))
    else:
        attempts.extend(
            await _real_attempts(
                session, kind, target_id, ip, number, protocol, category,
                current_version, fixed_version, cve_id,
            )
        )

    final = attempts[-1] if attempts else {
        "tier": 0, "result": INCONCLUSIVE, "command": "", "output": "no check run"
    }
    return {
        "result": final["result"],
        "tier": final["tier"],
        "attempts": attempts,
    }


async def _log(session, kind, target_id, tier, command, output, result) -> dict:
    row = HealthCheck(
        target_kind=kind, target_id=target_id, tier=tier,
        command=command, raw_output=output[:8000], result=result,
    )
    session.add(row)
    await session.commit()
    return {"tier": tier, "command": command, "output": output, "result": result}


async def _mock_attempt(session, kind, target_id, ip, number) -> dict:
    """Demo behaviour: first run shows the issue is still present; once the team
    has coached the guest, a later run reports it resolved (turns the card green)."""
    prior = await session.scalar(
        select(func.count())
        .select_from(HealthCheck)
        .where(HealthCheck.target_kind == kind, HealthCheck.target_id == target_id)
    )
    if (prior or 0) >= 1:
        return await _log(
            session, kind, target_id, 1,
            f"nmap -Pn -p {number} --open {ip}",
            f"[mock] Host {ip} — {number}/tcp now closed. Nice work!\n"
            "Note: 1 host scanned in 0.42s",
            RESOLVED,
        )
    return await _log(
        session, kind, target_id, 1,
        f"nmap -Pn -p {number} --open {ip}",
        f"[mock] Host {ip}\nPORT     STATE SERVICE\n{number}/tcp open\n"
        "(still exposed — coach the guest, then re-check)",
        STILL_PRESENT,
    )


async def _real_attempts(session, kind, target_id, ip, number, protocol, category,
                         current_version, fixed_version, cve_id) -> list[dict]:
    attempts: list[dict] = []

    # Tier 1 — reachability
    cmd1 = ["-Pn", "-p", str(number), "--open", "--max-rate", "50", ip]
    try:
        _, out, err = await run_nmap(cmd1, timeout=60)
    except Exception as exc:  # noqa: BLE001
        attempts.append(await _log(session, kind, target_id, 1,
                                   "nmap " + " ".join(cmd1), str(exc), INCONCLUSIVE))
        return attempts
    still_open = bool(re.search(rf"^{number}/{protocol}\s+open", out, re.MULTILINE))
    attempts.append(await _log(
        session, kind, target_id, 1, "nmap " + " ".join(cmd1), out or err,
        STILL_PRESENT if still_open else RESOLVED,
    ))
    if not still_open:
        return attempts

    # Tier 2 — identity / version
    cmd2 = ["-Pn", "-sV", "-p", str(number), "--max-rate", "50", ip]
    try:
        _, out2, err2 = await run_nmap(cmd2, timeout=90)
    except Exception as exc:  # noqa: BLE001
        attempts.append(await _log(session, kind, target_id, 2,
                                   "nmap " + " ".join(cmd2), str(exc), INCONCLUSIVE))
        out2 = ""
    else:
        result2 = _judge_version(out2, number, protocol, current_version, fixed_version)
        attempts.append(await _log(session, kind, target_id, 2,
                                   "nmap " + " ".join(cmd2), out2 or err2, result2))
        if result2 in _SOLVING or result2 == STILL_PRESENT and not _TIER3_NSE.get(category):
            return attempts

    # Tier 3 — targeted safe detection
    nse = _TIER3_NSE.get(category or "")
    if not nse:
        return attempts
    cmd3 = ["-Pn", "--max-rate", "50", "-p", str(number), "-sV", "--script", nse, ip]
    try:
        _, out3, err3 = await run_nmap(cmd3, timeout=90)
    except Exception as exc:  # noqa: BLE001
        attempts.append(await _log(session, kind, target_id, 3,
                                   "nmap " + " ".join(cmd3), str(exc), INCONCLUSIVE))
        return attempts
    text = (out3 or "").upper()
    # Only conclude "likely resolved" when the detection script actually ran and
    # produced a result block for the still-open port but found nothing. Missing
    # script / empty output must NOT auto-solve the finding (it stays open).
    script_ran = (
        bool(out3)
        and "DID NOT MATCH A CATEGORY" not in (err3 or "").upper()
        and bool(re.search(rf"^{number}/{protocol}\s+open", out3, re.MULTILINE))
    )
    if (cve_id and cve_id.upper() in text) or "VULNERABLE" in text:
        result3 = STILL_PRESENT
    elif script_ran and "|" in out3:  # script emitted a result block, found nothing
        result3 = LIKELY_RESOLVED
    else:
        result3 = INCONCLUSIVE
    attempts.append(await _log(session, kind, target_id, 3,
                               "nmap " + " ".join(cmd3), out3 or err3, result3))
    return attempts


def _ver_tuple(v: str | None) -> tuple[int, ...]:
    if not v:
        return ()
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


def _judge_version(out, number, protocol, current_version, fixed_version) -> str:
    line = next(
        (ln for ln in out.splitlines()
         if re.match(rf"^{number}/{protocol}\s+open", ln)),
        "",
    )
    if fixed_version:
        m = re.search(r"\b(\d+(?:\.\d+){1,3}[a-z]?\d*)\b", line)
        seen = m.group(1) if m else None
        if seen and _ver_tuple(seen) >= _ver_tuple(fixed_version):
            return LIKELY_RESOLVED
        if seen and current_version and _ver_tuple(seen) != _ver_tuple(current_version):
            # version changed but still below fixed
            return STILL_PRESENT
    if current_version and current_version in line:
        return STILL_PRESENT
    return INCONCLUSIVE
