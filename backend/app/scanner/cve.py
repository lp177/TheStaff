"""CVE enrichment + healthcheck-category inference.

Enrichment order (hybrid, offline-first):
  1. vulners/vulscan already gave us the CVE id (+ maybe cvss) during the scan.
  2. Offline enrichment from a snapshot of fkie-cad/nvd-json-data-feeds in
     THESTAFF_NVD_DIR -> description, cvss, references.
  3. (optional) online NVD top-up is intentionally out of the hot path.

The offline index is tolerant of several on-disk layouts (single-CVE files,
NVD 2.0 feed files with a "vulnerabilities" array, plain {id: detail} maps).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ..config import settings
from .types import ParsedCVE, ParsedHost

log = logging.getLogger("thestaff.cve")

# cve_id -> {"summary", "cvss", "references": [...], "fixed_version"}
_NVD_INDEX: dict[str, dict] = {}
_INDEX_LOADED = False


def load_nvd_index(force: bool = False) -> int:
    """Load the offline NVD snapshot into memory. Returns number of CVEs indexed."""
    global _INDEX_LOADED
    if _INDEX_LOADED and not force:
        return len(_NVD_INDEX)
    _NVD_INDEX.clear()
    nvd_dir = settings.nvd_dir
    if nvd_dir.exists():
        for path in sorted(nvd_dir.rglob("*.json")):
            try:
                _ingest_file(path)
            except (ValueError, OSError) as exc:
                log.warning("skipping NVD file %s: %s", path, exc)
    _INDEX_LOADED = True
    if _NVD_INDEX:
        log.info("offline NVD index: %d CVEs", len(_NVD_INDEX))
    else:
        log.info("no offline NVD feed found in %s (enrichment optional)", nvd_dir)
    return len(_NVD_INDEX)


def _ingest_file(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "vulnerabilities" in data:
        for item in data["vulnerabilities"]:
            _ingest_cve_obj(item.get("cve", item))
    elif isinstance(data, dict) and "cve" in data:
        _ingest_cve_obj(data["cve"])
    elif isinstance(data, list):
        for item in data:
            _ingest_cve_obj(item.get("cve", item) if isinstance(item, dict) else {})
    elif isinstance(data, dict) and data.get("id", "").upper().startswith("CVE-"):
        _ingest_cve_obj(data)
    elif isinstance(data, dict):
        # plain {cve_id: detail} map
        for key, val in data.items():
            if isinstance(key, str) and key.upper().startswith("CVE-") and isinstance(val, dict):
                _NVD_INDEX[key.upper()] = _normalize_detail(key.upper(), val)


def _ingest_cve_obj(cve: dict) -> None:
    cid = (cve.get("id") or cve.get("cve_id") or "").upper()
    if not cid.startswith("CVE-"):
        return
    _NVD_INDEX[cid] = _normalize_nvd2(cid, cve)


def _normalize_nvd2(cid: str, cve: dict) -> dict:
    summary = None
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            summary = d.get("value")
            break
    cvss = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            try:
                cvss = float(metrics[key][0]["cvssData"]["baseScore"])
                break
            except (KeyError, IndexError, TypeError, ValueError):
                continue
    refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]
    return {"summary": summary, "cvss": cvss, "references": refs[:8], "fixed_version": None}


def _normalize_detail(cid: str, val: dict) -> dict:
    return {
        "summary": val.get("summary") or val.get("description"),
        "cvss": val.get("cvss"),
        "references": val.get("references", [])[:8],
        "fixed_version": val.get("fixed_version"),
    }


# --- category inference (drives the healthcheck re-test tier) ---

_WEB_PORTS = {80, 443, 631, 5000, 5001, 8008, 8060, 8080, 8443, 32400}
_TLS_HINTS = ("tls", "ssl", "cipher", "certificate", "heartbleed")


def infer_category(port_number: int, service: str | None, summary: str | None) -> str:
    svc = (service or "").lower()
    text = (summary or "").lower()

    if port_number in (139, 445) or "smb" in svc or "microsoft-ds" in svc or "netbios" in svc:
        return "smb"
    if any(h in text or h in svc for h in _TLS_HINTS):
        return "tls"
    if "ssh" in svc:
        return "version"
    if "denial of service" in text or "denial-of-service" in text:
        return "dos"
    if "injection" in text:
        return "injection"
    if "ftp" in svc or "telnet" in svc:
        return "creds"
    if port_number in _WEB_PORTS or "http" in svc or "ipp" in svc:
        return "http"
    return "version"


def enrich(hosts: list[ParsedHost]) -> None:
    """Fill summary / references / cvss / category for every parsed CVE in place."""
    load_nvd_index()
    for host in hosts:
        for port in host.ports:
            for cve in port.cves:
                _enrich_one(port.number, port.service, cve)


def _enrich_one(port_number: int, service: str | None, cve: ParsedCVE) -> None:
    detail = _NVD_INDEX.get(cve.cve_id.upper())
    if detail:
        if not cve.summary and detail.get("summary"):
            cve.summary = detail["summary"]
        if cve.cvss is None and detail.get("cvss") is not None:
            cve.cvss = detail["cvss"]
        if not cve.references and detail.get("references"):
            cve.references = detail["references"]
        if not cve.fixed_version and detail.get("fixed_version"):
            cve.fixed_version = detail["fixed_version"]

    if not cve.references:
        cve.references = [f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}"]
    if not cve.summary:
        cve.summary = f"{cve.cve_id} affecting {service or 'this service'} (see references)."
    if not cve.category:
        cve.category = infer_category(port_number, service, cve.summary)
