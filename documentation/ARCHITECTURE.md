# TheStaff — Architecture

## Scan pipeline (one cycle)

Driven by an APScheduler interval job (`SCAN_INTERVAL_MIN`, default 15) and by
`POST /api/scan/now`. Implemented in `backend/app/scan_cycle.py`:

1. **Discover** (`scanner/runner.py`) — real mode runs nmap stage 1
   `nmap -sn -PR -n -T4 <cidr>` for live hosts, then stage 2
   `nmap -sS -sV -O --osscan-guess --version-light -p <ports> --script vulners,vulscan/vulscan.nse`.
   Mock mode (`scanner/mock.py`) returns a synthetic LAN instead.
2. **Parse** (`scanner/parse.py`) — host/port/OS via python-libnmap; the `vulners`
   (NSE `<table>`) and `vulscan` (delimited text) CVE blocks via `xml.etree.ElementTree`,
   joined back to ports by `(ip, portid)`.
3. **Fingerprint** (`scanner/fingerprint.py`) — weighted scoring over MAC-OUI vendor,
   nmap `osclass`, open-port patterns, mDNS, and gateway match → a device type
   (`router`, `printer`, `tv_streaming`, `phone_tablet`, `computer`, `nas`, `game_console`,
   `ip_camera`, `voip_phone`, `iot`, `unknown`).
4. **CVE map/enrich** (`scanner/cve.py`) — dedupe CVE IDs; enrich description/CVSS/refs
   from the offline `data/nvd/` snapshot when present; infer a healthcheck **category**
   (`smb`/`http`/`tls`/`version`/`creds`/`openport`/`dos`/`injection`).
5. **Reconcile** (`scanner/reconcile.py`) — upsert by natural key and apply the state
   machine; broadcast a fresh snapshot over the WebSocket.

## State machine (`backend/app/models.py`)

```
        scan detects                scan: absent / healthcheck RESOLVED
  ───────────────────────►  open  ─────────────────────────────►  solved
                             │ ▲                                     │
            operator accept  │ │ scan re-detects (regression)        │
                             ▼ │                                     │
                          accepted ◄──────── operator accept ───────┘
```
- **open** 🔴 detected, unresolved.
- **solved** 🟢 absent in a scan of a *present* host, or a healthcheck reported
  RESOLVED/LIKELY_RESOLVED. (A host that went offline entirely is left untouched — we can't
  infer "fixed" from absence.)
- **accepted** 🔵 operator-set; **never** auto-changed by scans.

Tables: `Host 1—* Port 1—* CVE`, plus `HealthCheck` (audit log) and `ConsentRecord`.
A host's diagram color is the worst of its children (`serialize.worst_state`).

## Healthcheck (`scanner/healthcheck.py`)

Tiered, non-destructive, fully audited:
1. **Reachability** — is the port still open? (closed ⇒ solved)
2. **Identity** — does the banner still show a vulnerable version? (≥ fixed ⇒ likely solved)
3. **Detection** — re-run the single safe NSE script for the CVE category.

Guardrails: single host/port, `--max-rate 50`, 60s timeout, only `safe`/`vuln` scripts —
**never** `exploit`/`dos`/`intrusive`, never `unsafe=1`. Every attempt is logged to the
`HealthCheck` table and shown in the UI. Mock mode simulates: first run STILL_PRESENT, a
later run RESOLVED (so the demo tells a "coach then verify" story).

## Web layer

- **FastAPI** (`main.py`): lifespan inits the DB (WAL) + offline NVD index + scheduler,
  mounts REST under `/api`, the `/ws` WebSocket, and serves the built Vue SPA (history-mode
  fallback to `index.html`).
- **WebSocket** (`ws.py`): in-memory `ConnectionManager` (no Redis). Snapshot on connect;
  after any change a fresh snapshot with a monotonically increasing `rev` is broadcast.
- **Serialization** (`serialize.py`): the single host/port/cve JSON contract shared by REST,
  WS, and the frontend `types.ts`.

## Frontend (`frontend/src`)

- **Pinia store** (`stores/devices.ts`) owns one reconnecting WebSocket and all state.
- **NetworkMap** uses `@vue-flow/core` with a custom **DeviceCard** node; layout is plain-trig
  radial (`lib/layout.ts`) — guests ringed around a central hub, no dagre/elk.
- **DetailView** is a native `<dialog>` (modal, `closedby="any"` + a JS light-dismiss
  fallback) showing ports/CVEs with accept-confirm, healthcheck, fix advice, and test commands.
- **ConsentPage** is the honest opt-in screen.

## Deployment

Rootful Podman, `--network=host`, `--cap-drop=ALL --cap-add=NET_RAW`, read-only rootfs,
`no-new-privileges`. Rootless cannot open the raw sockets nmap needs. See `deploy/` + `scripts/`.
