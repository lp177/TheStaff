"""Orchestrates one scan cycle: discover -> parse -> fingerprint -> CVEs ->
reconcile -> broadcast. Driven by the APScheduler interval job and by the
``POST /api/scan/now`` endpoint."""

from __future__ import annotations

import asyncio
import logging

from .config import settings
from .db import session_scope
from .scanner.cve import enrich
from .scanner.fingerprint import fingerprint_all
from .scanner.mock import MOCK_GATEWAY, generate_mock_lan
from .scanner.netdetect import resolve_cidr
from .scanner.parse import merge_hostnames, parse_scan
from .scanner.reconcile import reconcile
from .scanner.runner import default_gateway, nmap_available, run_nmap
from .scanner.types import ParsedHost
from .ws import manager

log = logging.getLogger("thestaff.scan")

_scan_lock = asyncio.Lock()
_rescan_pending = False


async def scan_cycle() -> dict:
    """Run a single scan cycle. Guarded so cycles never overlap. If a trigger
    arrives mid-cycle (e.g. a device was just added), one more cycle is queued to
    run as soon as the current one finishes — so a just-added host gets scanned."""
    global _rescan_pending
    if _scan_lock.locked():
        _rescan_pending = True
        log.info("scan already running; queued a re-run for when it finishes")
        return {"skipped": True, "queued": True}

    async with _scan_lock:
        try:
            if settings.is_mock or not nmap_available():
                parsed, gateway = generate_mock_lan(), MOCK_GATEWAY
                if not settings.is_mock:
                    log.warning("nmap unavailable; falling back to mock data")
            else:
                parsed, gateway = await _real_scan()

            fingerprint_all(parsed, gateway)
            enrich(parsed)

            async with session_scope() as session:
                stats = await reconcile(session, parsed)

            await manager.broadcast()
            stats["hosts"] = len(parsed)
            result = stats
        except Exception:  # noqa: BLE001
            log.exception("scan cycle failed")
            result = {"error": True}

    if _rescan_pending:
        _rescan_pending = False
        asyncio.create_task(scan_cycle())
    return result


async def _real_scan() -> tuple[list[ParsedHost], str | None]:
    scan_dir = settings.scan_dir
    discovery_xml = str(scan_dir / "discovery.xml")
    scan_xml = str(scan_dir / "scan.xml")

    cidr = resolve_cidr(settings.target_cidr)
    settings.effective_cidr = cidr

    # Stage 1 — fast ARP host discovery (only when there's a LAN CIDR to sweep).
    live_ips: list[str] = []
    if cidr:
        rc, _, err = await run_nmap(
            ["-sn", "-PR", "-n", "-T4", cidr, "-oX", discovery_xml], timeout=300
        )
        live_ips = _live_ips(discovery_xml)
        log.info("discovery: %d live host(s) in %s (rc=%d)", len(live_ips), cidr, rc)
    else:
        log.info("no scannable LAN CIDR detected; scanning manual hosts only")

    # Always also scan operator-added (manual) hosts — even outside the CIDR or
    # not ARP-reachable (e.g. a dedicated server with a public IP). This runs even
    # when no CIDR resolves, which is exactly the manual public-IP use case.
    manual_ips = await _manual_ips()
    targets = list(dict.fromkeys([*live_ips, *manual_ips]))  # dedup, keep order
    if manual_ips:
        log.info("including %d manual host(s) as scan targets", len(manual_ips))
    if not targets:
        return [], await default_gateway()

    # Stage 2 — fingerprint + service/version + CVE detection.
    base = [
        "-sS", "-sV", "-O", "--osscan-guess", "--version-light",
        "-T4", "--max-retries", "2", "--host-timeout", "90s",
        "-p", settings.ports,
    ]
    scripts: list[str] = []
    if settings.nse_scripts:
        scripts += ["--script", settings.nse_scripts]
        if settings.nse_args:
            scripts += ["--script-args", settings.nse_args]
    tail = ["-oX", scan_xml, *targets]
    timeout = max(600, 120 * max(1, len(targets) // 8))

    rc, _, err = await run_nmap(base + scripts + tail, timeout=timeout)
    if rc != 0 and scripts:
        # NSE failure shouldn't lose the whole scan — retry without CVE scripts
        # so devices/ports still appear (just without CVE annotations this cycle).
        log.warning(
            "stage-2 scan with NSE failed (rc=%d); retrying without scripts. "
            "stderr: %s", rc, (err or "").strip()[-300:],
        )
        rc, _, err = await run_nmap(base + tail, timeout=timeout)

    parsed = parse_scan(scan_xml)
    log.info(
        "stage-2: parsed %d host(s) from %d live IP(s) (rc=%d)",
        len(parsed), len(live_ips), rc,
    )

    if settings.name_enrichment:
        await _enrich_names(live_ips, parsed)

    return parsed, await default_gateway()


async def _manual_ips() -> list[str]:
    """IPs of operator-added (manual) hosts — always scanned, even outside the CIDR."""
    from sqlmodel import select

    from .models import Host

    async with session_scope() as session:
        rows = await session.execute(select(Host.ip).where(Host.manual.is_(True)))
        return [r[0] for r in rows.all()]


def _live_ips(discovery_xml: str) -> list[str]:
    try:
        from libnmap.parser import NmapParser

        rep = NmapParser.parse_fromfile(discovery_xml)
        return [h.address for h in rep.hosts if h.is_up()]
    except Exception:  # noqa: BLE001
        log.exception("failed to parse discovery output")
        return []


async def _enrich_names(live_ips: list[str], parsed: list[ParsedHost]) -> None:
    scan_dir = settings.scan_dir
    nbstat_xml = str(scan_dir / "nbstat.xml")
    mdns_xml = str(scan_dir / "mdns.xml")
    # Scope the broad except to the (expected-to-sometimes-fail) nmap call only;
    # let genuine bugs in merge_hostnames surface at warning level.
    try:
        await run_nmap(
            ["-sU", "-p137", "--script", "nbstat", "-oX", nbstat_xml, *live_ips],
            timeout=180,
        )
    except Exception:  # noqa: BLE001
        log.debug("nbstat scan skipped")
    else:
        try:
            merge_hostnames(parsed, nbstat_xml)
        except Exception:  # noqa: BLE001
            log.warning("nbstat hostname merge failed", exc_info=True)

    try:
        await run_nmap(
            ["-sU", "-p5353", "--script", "dns-service-discovery",
             "-oX", mdns_xml, *live_ips],
            timeout=180,
        )
    except Exception:  # noqa: BLE001
        log.debug("mDNS scan skipped")
    else:
        try:
            merge_hostnames(parsed, mdns_xml)
        except Exception:  # noqa: BLE001
            log.warning("mDNS hostname merge failed", exc_info=True)
