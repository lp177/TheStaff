"""FastAPI application entrypoint.

Wires: DB init (WAL), offline NVD index load, the APScheduler scan job, the
REST API under /api, the /ws WebSocket, and serving the built Vue SPA.
Run: ``uvicorn backend.app.main:app --host 0.0.0.0 --port 8000``
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import settings
from .db import init_db
from .routers import api_router
from .scanner.cve import load_nvd_index
from .scanner.runner import nmap_available
from .ws import ws_endpoint

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("thestaff")

REPO_ROOT = Path(__file__).resolve().parents[2]
DIST = REPO_ROOT / "frontend" / "dist"

scheduler = AsyncIOScheduler()


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("thestaff starting (mode=%s, nmap=%s)", settings.mode, nmap_available())
    settings.ensure_dirs()
    await init_db()
    load_nvd_index()

    if not settings.is_mock:
        from .scanner.netdetect import resolve_cidr

        settings.effective_cidr = resolve_cidr(settings.target_cidr)
        log.info(
            "scan target: %s (TARGET_CIDR=%s)",
            settings.effective_cidr or "UNRESOLVED — set TARGET_CIDR",
            settings.target_cidr,
        )

    from .scan_cycle import scan_cycle

    scheduler.add_job(
        scan_cycle, "interval", minutes=settings.scan_interval_min,
        id="scan", max_instances=1, coalesce=True,
    )
    scheduler.start()
    if settings.scan_on_start:
        import asyncio

        asyncio.create_task(scan_cycle())
    try:
        yield
    finally:
        scheduler.shutdown(wait=False)


app = FastAPI(title="thestaff", version="1.0.0", lifespan=lifespan)

if settings.dev_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.dev_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.include_router(api_router, prefix="/api")
app.add_api_websocket_route("/ws", ws_endpoint)


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True, "mode": settings.mode}


# --- SPA serving (registered last so /api and /ws win) ---
if DIST.exists():
    assets = DIST / "assets"
    if assets.exists():
        app.mount("/assets", StaticFiles(directory=str(assets)), name="assets")

    _DIST_RESOLVED = DIST.resolve()

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str):
        if full_path.startswith(("api/", "ws")):
            return JSONResponse({"detail": "not found"}, status_code=404)
        # Confine to the dist dir: reject any path that resolves outside it
        # (defends against ../ traversal from non-normalizing clients).
        if full_path:
            candidate = (_DIST_RESOLVED / full_path).resolve()
            if (
                candidate.is_file()
                and (candidate == _DIST_RESOLVED or _DIST_RESOLVED in candidate.parents)
            ):
                return FileResponse(str(candidate))
        return FileResponse(str(_DIST_RESOLVED / "index.html"))
else:
    @app.get("/", include_in_schema=False)
    async def no_build():
        return JSONResponse(
            {
                "detail": "Frontend not built. Run the Vite dev server "
                "(cd frontend && npm install && npm run dev) or build it "
                "(npm run build) to serve the SPA from here.",
                "api": "/api/hosts",
                "ws": "/ws",
            }
        )
