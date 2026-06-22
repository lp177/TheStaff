"""Runtime configuration, sourced from environment variables.

Kept deliberately dependency-light (no pydantic-settings) so the container
starts fast and the config surface is obvious to operators.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from pathlib import Path

log = logging.getLogger("thestaff.config")

# Categories we refuse to run from the scheduled scan path — keeps the
# detection-only promise structurally enforced even via env config.
_UNSAFE_NSE = re.compile(r"\b(exploit|dos|intrusive|brute|malware)\b|unsafe\s*=\s*1", re.I)
_PORTSPEC = re.compile(r"^[TUS]?:?\d{1,5}(-\d{1,5})?$")

# Default port set from the build spec: a spread that catches the device classes
# we fingerprint (printers, TVs/casting, NAS, phones, routers, computers, IoT).
DEFAULT_PORTS = (
    "22,53,80,139,443,445,515,554,631,1900,5000,5353,7000,"
    "8008,8009,8060,8443,9100,32400,49152,62078"
)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


class Settings:
    """Process-wide settings. Instantiated once as ``settings`` below."""

    def __init__(self) -> None:
        # "real" -> drive nmap against TARGET_CIDR.
        # "mock" -> generate a synthetic LAN so the app is fully demoable
        #           without a network, nmap, or container privileges.
        self.mode: str = os.getenv("THESTAFF_MODE", "mock").strip().lower()

        # Where runtime data lives (mounted volume in the container).
        self.data_dir: Path = Path(os.getenv("THESTAFF_DATA_DIR", "data")).resolve()
        self.db_path: Path = Path(
            os.getenv("THESTAFF_DB_PATH", str(self.data_dir / "scanner.db"))
        )
        # Offline NVD enrichment feed (fkie-cad/nvd-json-data-feeds snapshot).
        self.nvd_dir: Path = Path(
            os.getenv("THESTAFF_NVD_DIR", str(self.data_dir / "nvd"))
        )
        # Directory for transient nmap XML output.
        self.scan_dir: Path = Path(
            os.getenv("THESTAFF_SCAN_DIR", str(self.data_dir / "scans"))
        )

        # Scan scope + cadence. "auto" => detect the LAN subnet at runtime
        # (see scanner/netdetect.py). effective_cidr holds the resolved value.
        self.target_cidr: str = os.getenv("TARGET_CIDR", "auto").strip()
        self.effective_cidr: str | None = None
        self.scan_interval_min: int = _env_int("SCAN_INTERVAL_MIN", 15)
        self.ports: str = os.getenv("THESTAFF_PORTS", DEFAULT_PORTS).strip()
        # Run a scan immediately on startup (handy for demos / first boot).
        self.scan_on_start: bool = _env_bool("THESTAFF_SCAN_ON_START", True)

        # NSE scripts for CVE detection. Empty string disables script scanning
        # (useful for real runs where vulners/vulscan aren't installed).
        self.nse_scripts: str = os.getenv(
            "THESTAFF_NSE", "vulners,vulscan/vulscan.nse"
        ).strip()
        # NB: do NOT use vulscan's "{...}" output template here — nmap parses
        # "{" as a Lua table and the whole NSE engine fails to initialize. We
        # parse vulscan's default output instead (see scanner/parse.py).
        self.nse_args: str = os.getenv(
            "THESTAFF_NSE_ARGS",
            "vulners.mincvss=0.0,vulscandb=cve.csv",
        ).strip()
        # Opportunistic mDNS/NetBIOS name enrichment pass (real mode only).
        self.name_enrichment: bool = _env_bool("THESTAFF_NAME_ENRICH", True)

        # Allow the opportunistic online NVD/vulners top-up for CVEs missing
        # from the offline feed. Off by default (events often have flaky wifi).
        self.online_enrichment: bool = _env_bool("THESTAFF_ONLINE_ENRICH", False)

        # Show the network's public/WAN IP on the central node. A directly-bound
        # public IP is always detected egress-free; when none is found this makes
        # a single cached request to an external echo service to learn the NAT
        # address — the only place thestaff reaches beyond the LAN. Set to 0
        # to keep it fully offline (the node then shows "Private closed network").
        self.public_ip_lookup: bool = _env_bool("THESTAFF_PUBLIC_IP_LOOKUP", True)

        # Operator "Ask AI about this CVE" helper. The browser holds the API key
        # (Claude/OpenAI) and sends it per request; the backend proxies to the
        # provider (needed because OpenAI blocks browser CORS) and never stores
        # it. Set to 0 to disable the proxy entirely (fully offline events).
        self.ai_proxy: bool = _env_bool("THESTAFF_AI_PROXY", True)

        # Consent / branding shown on the opt-in page.
        self.organizer: str = os.getenv("THESTAFF_ORGANIZER", "the event team")
        self.organizer_email: str = os.getenv(
            "THESTAFF_ORGANIZER_EMAIL", "security@example.org"
        )
        self.ssid: str = os.getenv("THESTAFF_SSID", "thestaff-challenge")
        self.event_name: str = os.getenv("THESTAFF_EVENT", "the event")

        # How consent is established:
        #   "wifi" - possessing/using the WiFi password = consent (established
        #            out-of-band via signage/briefing). Headless/IoT devices are
        #            enrolled simply by connecting; the web page is informational.
        #   "http" - per-device explicit opt-in via the consent page checkbox.
        self.consent_mode: str = os.getenv("THESTAFF_CONSENT_MODE", "wifi").strip().lower()

        # Optional operator token. When set, all mutating / active-scan-trigger
        # endpoints require the X-Admin-Token header. Unset = open (dev/trusted).
        self.admin_token: str = os.getenv("THESTAFF_ADMIN_TOKEN", "").strip()

        self._sanitize()

        # CORS origins for split frontend dev server (vite on :5173).
        self.dev_origins: list[str] = [
            o.strip()
            for o in os.getenv(
                "THESTAFF_DEV_ORIGINS",
                "http://localhost:5173,http://127.0.0.1:5173",
            ).split(",")
            if o.strip()
        ]

    @property
    def is_mock(self) -> bool:
        return self.mode == "mock"

    @property
    def db_url(self) -> str:
        return f"sqlite+aiosqlite:///{self.db_path}"

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.nvd_dir, self.scan_dir):
            d.mkdir(parents=True, exist_ok=True)

    def _sanitize(self) -> None:
        """Validate operator-supplied scan inputs; fall back to safe defaults."""
        if self.target_cidr.lower() != "auto":
            try:
                ipaddress.ip_network(self.target_cidr, strict=False)
            except ValueError:
                log.warning("invalid TARGET_CIDR %r; using auto-detection", self.target_cidr)
                self.target_cidr = "auto"

        bad_ports = [p for p in self.ports.split(",") if p and not _PORTSPEC.match(p.strip())]
        if bad_ports:
            log.warning("invalid port spec %r; using defaults", self.ports)
            self.ports = DEFAULT_PORTS

        if self.nse_scripts and _UNSAFE_NSE.search(self.nse_scripts):
            log.warning(
                "THESTAFF_NSE %r requests exploit/dos/intrusive scripts; "
                "refusing (detection-only). Using vulners,vulscan only.",
                self.nse_scripts,
            )
            self.nse_scripts = "vulners,vulscan/vulscan.nse"
        if self.nse_args and _UNSAFE_NSE.search(self.nse_args):
            log.warning("THESTAFF_NSE_ARGS requests unsafe=1; stripping it")
            self.nse_args = re.sub(r",?\s*unsafe\s*=\s*1", "", self.nse_args).strip(", ")

        if self.consent_mode not in {"wifi", "http"}:
            log.warning("invalid THESTAFF_CONSENT_MODE %r; using 'wifi'", self.consent_mode)
            self.consent_mode = "wifi"


settings = Settings()
