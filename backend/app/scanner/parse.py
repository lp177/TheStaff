"""Parse nmap XML into ParsedHost objects.

- Host / port / service / OS classes: python-libnmap (object model).
- vulners / vulscan NSE results: stdlib ElementTree (the script <table>/output
  blocks are easier to read directly), joined back to ports by (ip, portid).

libnmap is imported lazily so mock mode works without the dependency installed.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET

from .types import ParsedCVE, ParsedHost, ParsedPort

log = logging.getLogger("thestaff.parse")

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def parse_scan(scan_xml: str) -> list[ParsedHost]:
    """Parse a Stage-2 scan XML into fingerprint-ready ParsedHost objects."""
    hosts = _parse_hosts(scan_xml)
    by_ip = {h.ip: h for h in hosts}
    _attach_cves(scan_xml, by_ip)
    return hosts


def _parse_hosts(scan_xml: str) -> list[ParsedHost]:
    try:
        from libnmap.parser import NmapParser
    except ImportError as exc:  # pragma: no cover - only in mock-only installs
        raise RuntimeError(
            "python-libnmap is required to parse real nmap output"
        ) from exc

    rep = NmapParser.parse_fromfile(scan_xml)
    out: list[ParsedHost] = []
    for h in rep.hosts:
        if not h.is_up():
            continue
        osclass = None
        try:
            if h.os and h.os.osclasses:
                osclass = h.os.osclasses[0]
        except Exception:  # noqa: BLE001 - libnmap can raise on absent os blocks
            osclass = None

        ports: list[ParsedPort] = []
        for svc in h.services:
            if svc.state != "open":
                continue
            banner = svc.banner_dict if hasattr(svc, "banner_dict") else {}
            cpe = None
            try:
                if svc.cpelist:
                    cpe = svc.cpelist[0].cpestring
            except Exception:  # noqa: BLE001
                cpe = None
            ports.append(
                ParsedPort(
                    number=svc.port,
                    protocol=svc.protocol,
                    service=svc.service or None,
                    product=banner.get("product"),
                    version=banner.get("version"),
                    cpe=cpe,
                )
            )

        out.append(
            ParsedHost(
                ip=h.address,
                mac=h.mac or None,
                vendor=(h.vendor or None),
                hostnames=list(h.hostnames) if h.hostnames else [],
                devicetype=getattr(osclass, "type", None),
                osfamily=getattr(osclass, "osfamily", None),
                osaccuracy=int(getattr(osclass, "accuracy", 0) or 0),
                ports=ports,
            )
        )
    return out


def _attach_cves(scan_xml: str, by_ip: dict[str, ParsedHost]) -> None:
    """Merge vulners (tables) + vulscan (text) CVEs into the parsed ports."""
    try:
        root = ET.parse(scan_xml).getroot()
    except (ET.ParseError, FileNotFoundError) as exc:
        log.warning("could not parse scan xml for CVEs: %s", exc)
        return

    for host_el in root.findall("host"):
        # NB: explicit None test — a childless Element is falsy, so `or` would
        # always fall through and defeat the ipv4 preference.
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr")
        host = by_ip.get(ip)
        if host is None:
            continue
        port_index = {(p.number, p.protocol): p for p in host.ports}

        for port_el in host_el.findall(".//port"):
            try:
                pid = int(port_el.get("portid"))
            except (TypeError, ValueError):
                continue
            proto = port_el.get("protocol", "tcp")
            target = port_index.get((pid, proto))
            if target is None:
                continue
            found: dict[str, ParsedCVE] = {}
            for script in port_el.findall("script[@id='vulners']"):
                for cve in _parse_vulners_script(script):
                    found[cve.cve_id] = cve
            for script in port_el.findall("script[@id='vulscan']"):
                for cve in _parse_vulscan_script(script):
                    found.setdefault(cve.cve_id, cve)
            target.cves = list(found.values())


def _parse_vulners_script(script: ET.Element) -> list[ParsedCVE]:
    out: list[ParsedCVE] = []
    for cpe_tbl in script.findall("table"):
        cpe = cpe_tbl.get("key")
        for vuln in cpe_tbl.findall("table"):
            g = {e.get("key"): (e.text or "") for e in vuln.findall("elem")}
            if g.get("type", "").lower() != "cve":
                continue
            cve_id = g.get("id")
            if not cve_id or not CVE_RE.fullmatch(cve_id):
                continue
            cvss = None
            try:
                cvss = float(g["cvss"]) if g.get("cvss") else None
            except ValueError:
                cvss = None
            out.append(
                ParsedCVE(
                    cve_id=cve_id.upper(),
                    cvss=cvss,
                    is_exploit=g.get("is_exploit", "").lower() == "true",
                    source="vulners",
                    cpe=cpe,
                )
            )
    return out


def _parse_vulscan_script(script: ET.Element) -> list[ParsedCVE]:
    # Template-agnostic: pull every CVE id out of vulscan's (default-format)
    # output. CVSS is left to the enrichment stage (offline NVD), since the
    # default output doesn't reliably carry a score.
    out: list[ParsedCVE] = []
    seen: set[str] = set()
    for m in CVE_RE.finditer(script.get("output") or ""):
        cid = m.group(0).upper()
        if cid not in seen:
            seen.add(cid)
            out.append(ParsedCVE(cve_id=cid, cvss=None, source="vulscan"))
    return out


def merge_hostnames(hosts: list[ParsedHost], names_xml: str) -> None:
    """Best-effort merge of nbstat/mDNS hostnames into existing hosts."""
    try:
        root = ET.parse(names_xml).getroot()
    except (ET.ParseError, FileNotFoundError):
        return
    by_ip = {h.ip: h for h in hosts}
    for host_el in root.findall("host"):
        # NB: explicit None test — a childless Element is falsy, so `or` would
        # always fall through and defeat the ipv4 preference.
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address")
        if addr_el is None:
            continue
        host = by_ip.get(addr_el.get("addr"))
        if host is None:
            continue
        for hn in host_el.findall(".//hostname"):
            name = hn.get("name")
            if name and name not in host.hostnames:
                host.hostnames.append(name)
        # mDNS service types from dns-service-discovery output
        for script in host_el.findall(".//script[@id='dns-service-discovery']"):
            for token in re.findall(r"_[a-z0-9-]+\._(?:tcp|udp)", script.get("output") or ""):
                if token not in host.mdns:
                    host.mdns.append(token)
