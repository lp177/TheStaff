"""Auto-detect the LAN subnet to scan.

Picks the private IPv4 network of a real, physical-ish interface — preferring the
one carrying the default route — while excluding virtual/VPN/container
interfaces (docker, bridges, veth, wireguard, tun/tap, etc.). Reports all
candidates so ambiguity can be surfaced and overridden via TARGET_CIDR.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import subprocess
import urllib.request

log = logging.getLogger("thestaff.netdetect")

# Interface names that are never the event LAN we want to scan.
_VIRTUAL_PREFIXES = (
    "lo", "docker", "br-", "veth", "virbr", "cni", "flannel", "kube",
    "wg", "tun", "tap", "ppp", "zt", "tailscale", "nordlynx", "utun",
)


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=5, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _is_virtual(iface: str) -> bool:
    return iface == "lo" or any(iface.startswith(p) for p in _VIRTUAL_PREFIXES)


def _default_iface() -> str | None:
    for line in _run(["ip", "-o", "-4", "route", "show", "default"]).splitlines():
        parts = line.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    return None


def _iface_networks() -> list[tuple[str, ipaddress.IPv4Interface]]:
    out: list[tuple[str, ipaddress.IPv4Interface]] = []
    for line in _run(["ip", "-o", "-4", "addr", "show"]).splitlines():
        parts = line.split()
        if "inet" not in parts or len(parts) < 2:
            continue
        iface = parts[1]
        cidr = parts[parts.index("inet") + 1]
        try:
            out.append((iface, ipaddress.ip_interface(cidr)))
        except ValueError:
            continue
    return out


def detect_lan() -> dict:
    """Return {cidr, default_iface, candidates, ambiguous}. cidr may be None."""
    default_if = _default_iface()
    candidates: list[tuple[str, str]] = []
    for iface, ipi in _iface_networks():
        if _is_virtual(iface) or not ipi.ip.is_private:
            continue
        candidates.append((iface, str(ipi.network)))

    seen: set[str] = set()
    uniq: list[tuple[str, str]] = []
    for iface, net in candidates:
        if net not in seen:
            seen.add(net)
            uniq.append((iface, net))

    chosen: str | None = None
    if default_if:
        chosen = next((net for iface, net in uniq if iface == default_if), None)
    if chosen is None and uniq:
        chosen = uniq[0][1]

    return {
        "cidr": chosen,
        "default_iface": default_if,
        "candidates": [net for _, net in uniq],
        "ambiguous": len(uniq) > 1,
    }


# cached resolved target so we don't re-shell every cycle
_resolved: str | None = None


def resolve_cidr(configured: str) -> str | None:
    """Resolve the CIDR to scan. ``configured`` is settings.target_cidr.

    If it's a real CIDR, use it verbatim. If it's "auto" (or empty), detect.
    """
    global _resolved
    if configured and configured.strip().lower() != "auto":
        return configured.strip()
    if _resolved:
        return _resolved

    info = detect_lan()
    cidr = info["cidr"]
    if not cidr:
        log.error(
            "could not auto-detect a LAN to scan (no private, non-virtual IPv4 "
            "interface found). Set TARGET_CIDR explicitly."
        )
        return None
    if info["ambiguous"]:
        log.warning(
            "multiple LANs detected %s; scanning %s (default-route iface %s). "
            "Set TARGET_CIDR to override.",
            info["candidates"], cidr, info["default_iface"],
        )
    else:
        log.info("auto-detected scan target %s (iface %s)", cidr, info["default_iface"])
    _resolved = cidr
    return cidr


# --- public / WAN IP detection -------------------------------------------------
#
# The central "Event network" node shows the network's public IP when one can be
# found, otherwise "Private closed network". Two tiers, cheapest first:
#   1. egress-free: a globally-routable IPv4 assigned directly to a local iface.
#   2. egress lookup: ask an external echo service for the NAT/WAN address.
# Tier 2 is the *only* place thestaff may reach beyond the LAN; it is gated by
# THESTAFF_PUBLIC_IP_LOOKUP, never runs in mock mode, and the result is cached.

_PUBLIC_IP_SERVICES = (
    "https://api.ipify.org",
    "https://icanhazip.com",
    "https://ifconfig.me/ip",
)

_public_ip: str | None = None
_public_ip_resolved = False
_public_ip_lock: asyncio.Lock | None = None


def _local_public_ip() -> str | None:
    """A globally-routable IPv4 bound to a non-virtual local interface (no NAT)."""
    for iface, ipi in _iface_networks():
        if not _is_virtual(iface) and ipi.ip.is_global:
            return str(ipi.ip)
    return None


def _egress_public_ip(timeout: float = 4.0) -> str | None:
    """Ask an external echo service for our NAT/WAN address (best-effort)."""
    for url in _PUBLIC_IP_SERVICES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "thestaff"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                text = resp.read(64).decode("utf-8", "ignore").strip()
            ip = ipaddress.ip_address(text)
            if ip.is_global:
                return str(ip)
        except Exception:  # noqa: BLE001 — any failure just means "no public IP"
            continue
    return None


def detect_public_ip(allow_egress: bool) -> str | None:
    """Blocking detection: local public IP, then (optionally) an egress lookup."""
    local = _local_public_ip()
    if local:
        return local
    if allow_egress:
        return _egress_public_ip()
    return None


async def get_public_ip(allow_egress: bool) -> str | None:
    """Cached, non-blocking public-IP detection (runs the probe once, off-loop)."""
    global _public_ip, _public_ip_resolved, _public_ip_lock
    if _public_ip_resolved:
        return _public_ip
    if _public_ip_lock is None:
        _public_ip_lock = asyncio.Lock()
    async with _public_ip_lock:
        if _public_ip_resolved:
            return _public_ip
        loop = asyncio.get_running_loop()
        _public_ip = await loop.run_in_executor(None, detect_public_ip, allow_egress)
        _public_ip_resolved = True
        if _public_ip:
            log.info("detected public IP for the event network: %s", _public_ip)
        return _public_ip


def reset_cache() -> None:
    global _resolved, _public_ip, _public_ip_resolved
    _resolved = None
    _public_ip = None
    _public_ip_resolved = False
