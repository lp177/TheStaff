"""Run nmap as a non-blocking async subprocess.

We never use python-nmap's blocking ``scan()`` from the event loop; nmap is an
external binary driven via ``asyncio.create_subprocess_exec``.
"""

from __future__ import annotations

import asyncio
import logging
import shutil

log = logging.getLogger("thestaff.runner")


class NmapNotInstalled(RuntimeError):
    pass


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


async def run_nmap(args: list[str], timeout: float = 600.0) -> tuple[int, str, str]:
    """Run ``nmap <args>`` and return (returncode, stdout, stderr).

    Raises NmapNotInstalled if the binary is missing, and TimeoutError if the
    scan exceeds ``timeout`` seconds (the process is killed).
    """
    if not nmap_available():
        raise NmapNotInstalled("nmap binary not found on PATH")

    log.info("nmap %s", " ".join(args))
    proc = await asyncio.create_subprocess_exec(
        "nmap",
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, TimeoutError):
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"nmap timed out after {timeout}s")

    rc = proc.returncode or 0
    out = stdout.decode(errors="replace")
    err = stderr.decode(errors="replace")
    if rc != 0:
        log.warning("nmap exited %d: %s", rc, (err.strip() or out.strip())[-400:])
    elif "failed to initialize the script engine" in err or "did not parse" in err:
        log.warning("nmap NSE problem: %s", err.strip()[-400:])
    return rc, out, err


async def default_gateway() -> str | None:
    """Best-effort default-gateway IP (used to flag the router in fingerprinting)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "ip",
            "route",
            "show",
            "default",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await proc.communicate()
    except (FileNotFoundError, OSError):
        return None
    for line in out.decode(errors="replace").splitlines():
        parts = line.split()
        if "via" in parts:
            return parts[parts.index("via") + 1]
    return None
