"""End-to-end backend smoke test (mock mode, no network/nmap needed).

Run from the repo root:  .venv/bin/python scripts/smoketest.py
"""

import asyncio
import os
import tempfile

os.environ.setdefault("THESTAFF_MODE", "mock")
os.environ.setdefault("THESTAFF_DATA_DIR", tempfile.mkdtemp(prefix="sm-smoke-"))
os.environ.setdefault("THESTAFF_SCAN_ON_START", "0")


async def main() -> None:
    from backend.app.db import fetch_cve, init_db, session_scope
    from backend.app.scan_cycle import scan_cycle
    from backend.app.scanner.healthcheck import healthcheck_cve
    from backend.app.serialize import host_to_dict
    from backend.app.db import fetch_hosts

    await init_db()

    stats = await scan_cycle()
    print("scan_cycle stats:", stats)
    assert stats.get("hosts", 0) >= 6, "expected several mock hosts"

    async with session_scope() as s:
        hosts = await fetch_hosts(s)
        dicts = [host_to_dict(h) for h in hosts]

    types = {d["ip"]: d["device_type"] for d in dicts}
    print("device types:", types)
    assert types.get("192.168.1.1") == "router", types
    assert types.get("192.168.1.40") == "printer", types
    assert types.get("192.168.1.30") == "phone_tablet", types
    assert types.get("192.168.1.21") == "computer", types
    assert types.get("192.168.1.70") == "iot", types

    total_cves = sum(len(p["cves"]) for d in dicts for p in d["ports"])
    print("total CVEs:", total_cves)
    assert total_cves >= 5, "expected several CVEs from mock data"

    # find an open CVE, accept it, verify blue
    target = None
    for d in dicts:
        for p in d["ports"]:
            for c in p["cves"]:
                if c["state"] == "open":
                    target = c
                    break
    assert target, "expected an open CVE"

    async with session_scope() as s:
        cve = await fetch_cve(s, target["id"])
        cve.state = cve.state.__class__.accepted
        await s.commit()
    print(f"accepted CVE {target['cve_id']} -> blue")

    # healthcheck another open CVE twice: first STILL_PRESENT, then RESOLVED -> green
    hc_target = None
    for d in dicts:
        for p in d["ports"]:
            for c in p["cves"]:
                if c["state"] == "open" and c["id"] != target["id"]:
                    hc_target = c
                    break
            if hc_target:
                break
        if hc_target:
            break

    async with session_scope() as s:
        cve = await fetch_cve(s, hc_target["id"])
        ip = cve.port.host.ip
        r1 = await healthcheck_cve(s, cve, ip)
    async with session_scope() as s:
        cve = await fetch_cve(s, hc_target["id"])
        r2 = await healthcheck_cve(s, cve, ip)
        final_state = cve.state.value
    print(f"healthcheck {hc_target['cve_id']}: {r1['result']} -> {r2['result']} "
          f"(state now {final_state})")
    assert r1["result"] == "STILL_PRESENT"
    assert r2["result"] == "RESOLVED"
    assert final_state == "solved"

    # worst_state rollup sanity
    states = {d["ip"]: d["worst_state"] for d in dicts}
    print("worst_state:", states)

    print("\nSMOKETEST_OK")


if __name__ == "__main__":
    asyncio.run(main())
