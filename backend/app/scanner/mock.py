"""Synthetic LAN generator for demo / dev / CI.

Produces realistic ParsedHost objects (vendors, OS hints, open ports, and a
handful of real, well-known CVEs) so the entire app — diagram, detail view,
accept flow, healthcheck loop — works with no network, no nmap, and no
container privileges. Selected via THESTAFF_MODE=mock (the default).
"""

from __future__ import annotations

from .types import ParsedCVE, ParsedHost, ParsedPort

MOCK_GATEWAY = "192.168.1.1"


def _cve(cve_id, cvss, summary, category, *, source="mock", exploit=False,
         refs=None, fixed=None) -> ParsedCVE:
    return ParsedCVE(
        cve_id=cve_id,
        cvss=cvss,
        is_exploit=exploit,
        source=source,
        summary=summary,
        category=category,
        fixed_version=fixed,
        references=refs or [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
    )


def generate_mock_lan() -> list[ParsedHost]:
    return [
        # --- Gateway / router (AVM FRITZ!Box) ---
        ParsedHost(
            ip="192.168.1.1", mac="00:1A:2B:3C:4D:5E", vendor="AVM",
            hostnames=["fritz.box"], devicetype="broadband router",
            osfamily="FRITZ!OS", osaccuracy=96,
            ports=[
                ParsedPort(53, "udp", "domain", product="dnsmasq", version="2.78",
                    cves=[_cve("CVE-2017-14491", 9.8,
                              "dnsmasq heap overflow in DNS response handling — remote "
                              "code execution from a crafted reply.",
                              "version", exploit=True, fixed="2.78")]),
                ParsedPort(23, "tcp", "telnet"),  # legacy debug port left open, no CVE
                ParsedPort(
                    80, "tcp", "http", product="AVM FRITZ!Box http", version="7.20",
                    cves=[_cve("CVE-2020-12107", 8.8,
                              "FRITZ!OS command injection via the web interface.",
                              "http", exploit=True, fixed="7.21")],
                ),
                ParsedPort(
                    443, "tcp", "https", product="AVM FRITZ!Box", version="7.20",
                    cves=[_cve("CVE-2016-2107", 5.9,
                              "OpenSSL AES-NI padding-oracle (Lucky-13 variant) — "
                              "MITM can recover plaintext over TLS.",
                              "tls", fixed="1.0.2h")],
                ),
                ParsedPort(
                    7547, "tcp", "http", product="RomPager", version="4.07",
                    cpe="cpe:/a:allegrosoft:rompager:4.07",
                    cves=[
                        _cve("CVE-2014-9222", 10.0,
                             "RomPager 'Misfortune Cookie' — a crafted Cookie header "
                             "corrupts memory and lets a remote attacker take over the "
                             "device's TR-069/CWMP management server.",
                             "http", exploit=True, fixed="4.34"),
                        _cve("CVE-2014-9223", 9.8,
                             "RomPager authentication bypass exposing the device "
                             "management interface to unauthenticated requests.",
                             "http", exploit=True),
                    ],
                ),
                ParsedPort(1900, "udp", "upnp", product="MiniUPnPd", version="1.8"),
            ],
        ),
        # --- Linux laptop with an old OpenSSH ---
        ParsedHost(
            ip="192.168.1.20", mac="F0:18:98:11:22:33", vendor="Dell",
            hostnames=["alice-thinkpad"], devicetype="general purpose",
            osfamily="Linux", osaccuracy=95,
            ports=[
                ParsedPort(
                    22, "tcp", "ssh", product="OpenSSH", version="7.4",
                    cpe="cpe:/a:openbsd:openssh:7.4",
                    cves=[
                        _cve("CVE-2018-15473", 5.3,
                             "OpenSSH username enumeration via timing/response "
                             "differences.", "version", fixed="7.7"),
                        _cve("CVE-2016-10009", 7.5,
                             "OpenSSH agent forwarding arbitrary library loading.",
                             "version", exploit=True, fixed="7.4"),
                    ],
                ),
                ParsedPort(631, "tcp", "ipp", product="CUPS", version="2.2"),
            ],
        ),
        # --- Windows laptop with SMB exposed (EternalBlue) ---
        ParsedHost(
            ip="192.168.1.21", mac="3C:97:0E:44:55:66", vendor="LCFC",
            hostnames=["bob-pc"], devicetype="general purpose",
            osfamily="Windows", osaccuracy=92,
            ports=[
                ParsedPort(135, "tcp", "msrpc"),
                ParsedPort(139, "tcp", "netbios-ssn"),
                ParsedPort(
                    445, "tcp", "microsoft-ds", product="Windows SMB", version="1",
                    cves=[_cve("CVE-2017-0144", 8.1,
                              "SMBv1 remote code execution (EternalBlue / MS17-010).",
                              "smb", exploit=True,
                              refs=["https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
                                    "https://learn.microsoft.com/security-updates/"
                                    "securitybulletins/2017/ms17-010"])],
                ),
                ParsedPort(3389, "tcp", "ms-wbt-server", product="Microsoft Terminal Services"),
            ],
        ),
        # --- iPhone (opt-in, minimal surface, no CVEs -> good citizen) ---
        ParsedHost(
            ip="192.168.1.30", mac="A4:83:E7:77:88:99", vendor="Apple",
            hostnames=["carols-iphone"], devicetype="phone",
            osfamily="iOS", osaccuracy=90,
            ports=[ParsedPort(62078, "tcp", "iphone-sync")],
        ),
        # --- HP network printer ---
        ParsedHost(
            ip="192.168.1.40", mac="3C:52:82:AA:BB:CC", vendor="HP",
            hostnames=["hp-laserjet"], devicetype="printer",
            osfamily="embedded", osaccuracy=88, mdns=["_ipp._tcp"],
            ports=[
                ParsedPort(9100, "tcp", "jetdirect"),
                ParsedPort(
                    631, "tcp", "ipp", product="CUPS", version="2.4.1",
                    cves=[_cve("CVE-2024-47176", 8.6,
                              "cups-browsed binds to UDP *:631 and trusts attacker "
                              "data, leading to RCE when a print job runs.",
                              "http", fixed="2.4.11")],
                ),
                ParsedPort(80, "tcp", "http", product="HP Embedded Web Server"),
            ],
        ),
        # --- Smart TV (Chromecast-style) ---
        ParsedHost(
            ip="192.168.1.50", mac="54:60:09:DD:EE:FF", vendor="Google",
            hostnames=["living-room-tv"], devicetype="media device",
            osfamily="Android", osaccuracy=85, mdns=["_googlecast._tcp"],
            ports=[
                ParsedPort(8008, "tcp", "http"),
                ParsedPort(8009, "tcp", "ssl/castv2"),
            ],
        ),
        # --- Synology NAS ---
        ParsedHost(
            ip="192.168.1.60", mac="00:11:32:12:34:56", vendor="Synology",
            hostnames=["nas"], devicetype="storage-misc",
            osfamily="Linux", osaccuracy=90,
            ports=[
                ParsedPort(
                    5000, "tcp", "http", product="Synology DSM", version="6.2",
                    cves=[_cve("CVE-2021-26566", 6.5,
                              "Synology DSM improper input handling allowing "
                              "information disclosure.", "http", fixed="6.2.4")],
                ),
                ParsedPort(5001, "tcp", "https", product="Synology DSM", version="6.2"),
                ParsedPort(22, "tcp", "ssh", product="OpenSSH", version="8.2"),
            ],
        ),
        # --- IoT smart plug (ESP-based, only a tiny web server) ---
        ParsedHost(
            ip="192.168.1.70", mac="24:0A:C4:65:43:21", vendor="Espressif",
            hostnames=[], devicetype=None, osfamily=None, osaccuracy=0,
            ports=[
                ParsedPort(
                    80, "tcp", "http", product="ESP-IDF httpd",
                    cves=[_cve("CVE-2023-35818", 7.5,
                              "Espressif esp-idf exposed debug interface enabling "
                              "unauthenticated access.", "http")],
                ),
            ],
        ),
    ]
