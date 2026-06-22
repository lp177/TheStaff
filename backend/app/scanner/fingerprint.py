"""Weighted device-type fingerprinting.

Signals combined per candidate type (argmax wins, ties broken by table order):
  - is_gateway              host IP == default gateway
  - devtype:<x>             nmap osclass.type (piped values split)
  - osfamily:<x>            nmap osclass.osfamily
  - port:<n>                port n is open
  - oui:<vendor substring>  case-insensitive substring of the MAC-OUI vendor
  - mdns:<_svc._proto>      mDNS service type discovered
  - few_open_ports          <= 2 open ports
  - only_port_80            exactly one open port, 80
  - no_os_match             no osclass info at all
"""

from __future__ import annotations

from .types import ParsedHost

RULES: dict[str, list[tuple[str, int]]] = {
    "router": [
        ("is_gateway", 6),
        ("devtype:router", 4), ("devtype:WAP", 4), ("devtype:broadband router", 4),
        ("port:53", 2), ("port:7547", 3), ("port:1900", 1),
        ("oui:AVM", 3), ("oui:Netgear", 3), ("oui:TP-Link", 3),
        ("oui:Ubiquiti", 3), ("oui:Cisco", 3), ("oui:ASUS", 3),
        ("oui:MikroTik", 3), ("oui:D-Link", 3),
    ],
    "printer": [
        ("port:9100", 5), ("port:631", 4), ("port:515", 3),
        ("devtype:printer", 4), ("devtype:print server", 4),
        ("mdns:_ipp._tcp", 4), ("mdns:_printer._tcp", 4),
        ("oui:HP", 3), ("oui:Canon", 3), ("oui:Brother", 3),
        ("oui:Epson", 3), ("oui:Lexmark", 3), ("oui:Xerox", 3),
    ],
    "tv_streaming": [
        ("port:8008", 4), ("port:8009", 4), ("port:8060", 5),
        ("port:7000", 3), ("port:554", 2), ("port:32400", 2),
        ("devtype:media device", 4),
        ("mdns:_googlecast._tcp", 5), ("mdns:_airplay._tcp", 4),
        ("oui:Roku", 4), ("oui:Google", 2), ("oui:Amazon", 2),
        ("oui:Samsung", 1), ("oui:LG", 2), ("oui:Vizio", 3),
    ],
    "phone_tablet": [
        ("port:62078", 5),
        ("port:5353", 1),
        ("devtype:phone", 4), ("osfamily:iOS", 4), ("osfamily:Android", 4),
        ("oui:Apple", 3), ("oui:Samsung", 2), ("oui:Xiaomi", 3),
        ("oui:Huawei", 3), ("oui:Google", 2), ("oui:OnePlus", 3),
        ("few_open_ports", 1),
    ],
    "computer": [
        ("devtype:general purpose", 4),
        ("osfamily:Windows", 4), ("osfamily:macOS", 3),
        ("osfamily:Mac OS X", 3), ("osfamily:Linux", 2),
        ("port:139", 2), ("port:445", 2), ("port:22", 2),
        ("port:3389", 3), ("port:5900", 2),
    ],
    "nas": [
        ("port:5000", 3), ("port:5001", 3), ("port:548", 2), ("port:2049", 2),
        ("devtype:storage-misc", 3),
        ("oui:Synology", 4), ("oui:QNAP", 4),
        ("oui:Western Digital", 3), ("oui:Buffalo", 3),
    ],
    "game_console": [
        ("devtype:game console", 5),
        ("port:3074", 3), ("port:9295", 3),
        ("oui:Sony", 3), ("oui:Microsoft", 2), ("oui:Nintendo", 3),
    ],
    "ip_camera": [
        ("port:554", 3), ("port:8000", 2), ("port:37777", 4),
        ("devtype:webcam", 4),
        ("oui:Hikvision", 4), ("oui:Dahua", 4), ("oui:Axis", 4), ("oui:Reolink", 4),
    ],
    "voip_phone": [
        ("port:5060", 4), ("devtype:VoIP phone", 4),
        ("oui:Polycom", 3), ("oui:Yealink", 3), ("oui:Cisco", 1),
    ],
    "iot": [
        ("oui:Espressif", 4), ("oui:Tuya", 4), ("oui:Sonoff", 4),
        ("oui:Shelly", 4), ("oui:Signify", 4), ("oui:Nest", 3),
        ("port:1883", 3), ("port:8883", 3), ("port:1900", 1),
        ("only_port_80", 1), ("no_os_match", 1),
    ],
}

# Map a raw nmap osclass.type to our categories (fallback when scoring is flat).
_NMAP_TYPE_FALLBACK = {
    "router": "router",
    "WAP": "router",
    "broadband router": "router",
    "printer": "printer",
    "print server": "printer",
    "media device": "tv_streaming",
    "phone": "phone_tablet",
    "general purpose": "computer",
    "storage-misc": "nas",
    "game console": "game_console",
    "webcam": "ip_camera",
    "VoIP phone": "voip_phone",
    "VoIP adapter": "voip_phone",
}


def _signals(host: ParsedHost, gateway: str | None) -> set[str]:
    sig: set[str] = set()
    open_ports = {p.number for p in host.ports}
    for n in open_ports:
        sig.add(f"port:{n}")

    if gateway and host.ip == gateway:
        sig.add("is_gateway")

    for raw in (host.devicetype or "").split("|"):
        raw = raw.strip()
        if raw:
            sig.add(f"devtype:{raw}")
    if host.osfamily:
        sig.add(f"osfamily:{host.osfamily}")
    for svc in host.mdns:
        sig.add(f"mdns:{svc}")

    if len(open_ports) <= 2:
        sig.add("few_open_ports")
    if open_ports == {80}:
        sig.add("only_port_80")
    if not host.devicetype and not host.osfamily:
        sig.add("no_os_match")
    return sig


def _matches(rule_key: str, host: ParsedHost, signals: set[str]) -> bool:
    if rule_key.startswith("oui:"):
        wanted = rule_key[4:].lower()
        return bool(host.vendor) and wanted in host.vendor.lower()
    if rule_key.startswith(("devtype:", "osfamily:", "mdns:")):
        # case-insensitive match against the collected signals
        target = rule_key.lower()
        return any(s.lower() == target for s in signals)
    return rule_key in signals


def classify(host: ParsedHost, gateway: str | None = None) -> str:
    signals = _signals(host, gateway)
    best_type = "unknown"
    best_score = 0
    for device_type, rules in RULES.items():  # insertion order = tie-break priority
        score = sum(weight for key, weight in rules if _matches(key, host, signals))
        if score > best_score:
            best_score = score
            best_type = device_type

    if best_score > 0:
        return best_type

    # Flat score: fall back to nmap's own classification, else unknown.
    for raw in (host.devicetype or "").split("|"):
        mapped = _NMAP_TYPE_FALLBACK.get(raw.strip())
        if mapped:
            return mapped
    return "unknown"


def fingerprint_all(hosts: list[ParsedHost], gateway: str | None = None) -> None:
    for host in hosts:
        host.device_type = classify(host, gateway)
