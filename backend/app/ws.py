"""WebSocket connection manager + live snapshot broadcasting.

Single-process, in-memory (no Redis). On connect a client gets a full snapshot;
after every scan/state change we broadcast a fresh snapshot with a monotonic
revision. Snapshots are small (dozens of hosts) so we skip diffing for clarity.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import WebSocket, WebSocketDisconnect

from .db import fetch_hosts, session_scope
from .serialize import hosts_to_list

log = logging.getLogger("thestaff.ws")


async def build_snapshot(rev: int) -> dict:
    async with session_scope() as session:
        hosts = await fetch_hosts(session)
        return {"type": "snapshot", "rev": rev, "hosts": hosts_to_list(hosts)}


class ConnectionManager:
    def __init__(self) -> None:
        self._active: set[WebSocket] = set()
        self._lock = asyncio.Lock()
        self.rev = 0

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._active.add(ws)
        await ws.send_json(await build_snapshot(self.rev))
        log.info("ws client connected (%d total)", len(self._active))

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._active.discard(ws)

    async def broadcast(self) -> None:
        """Bump the revision and push a fresh snapshot to every client."""
        self.rev += 1
        snapshot = await build_snapshot(self.rev)
        async with self._lock:
            targets = list(self._active)
        dead: list[WebSocket] = []
        for ws in targets:
            try:
                await ws.send_json(snapshot)
            except Exception:  # noqa: BLE001 - client vanished mid-send
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._active.discard(ws)

    @property
    def count(self) -> int:
        return len(self._active)


manager = ConnectionManager()


async def ws_endpoint(ws: WebSocket) -> None:
    await manager.connect(ws)
    try:
        while True:
            msg = await ws.receive_json()
            if isinstance(msg, dict) and msg.get("type") == "resync":
                await ws.send_json(await build_snapshot(manager.rev))
            # any other inbound message is treated as a keepalive ping
    except WebSocketDisconnect:
        await manager.disconnect(ws)
    except Exception:  # noqa: BLE001
        await manager.disconnect(ws)
