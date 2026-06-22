"""Async SQLite layer (SQLModel + aiosqlite, WAL mode)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import selectinload
from sqlmodel import SQLModel, select

from .config import settings
from .models import CVE, Host, Port

engine = create_async_engine(settings.db_url, echo=False, future=True)

SessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


@event.listens_for(engine.sync_engine, "connect")
def _set_sqlite_pragmas(dbapi_conn, _record):  # noqa: ANN001
    """WAL + sane durability for a single-writer event-time workload."""
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA synchronous=NORMAL")
    cur.execute("PRAGMA foreign_keys=ON")
    cur.close()


async def _ensure_column(conn, table: str, column: str, ddl: str) -> None:
    """Add a column to an existing table if missing (SQLite, no Alembic)."""
    rows = (await conn.execute(text(f"PRAGMA table_info({table})"))).fetchall()
    if column not in {r[1] for r in rows}:
        await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))


async def init_db() -> None:
    settings.ensure_dirs()
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
        # Lightweight migrations for columns added after the initial release.
        await _ensure_column(conn, "host", "manual", "BOOLEAN NOT NULL DEFAULT 0")
        await conn.execute(text("PRAGMA journal_mode=WAL"))


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        yield session


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency."""
    async with SessionLocal() as session:
        yield session


_SNAPSHOT_LOADERS = (
    selectinload(Host.ports).selectinload(Port.cves),
)


async def fetch_hosts(session: AsyncSession) -> list[Host]:
    """All hosts with ports+cves eagerly loaded (safe to serialize after)."""
    result = await session.execute(
        select(Host).options(*_SNAPSHOT_LOADERS).order_by(Host.ip)
    )
    return list(result.scalars().all())


async def fetch_host(session: AsyncSession, host_id: int) -> Host | None:
    result = await session.execute(
        select(Host).where(Host.id == host_id).options(*_SNAPSHOT_LOADERS)
    )
    return result.scalars().first()


async def fetch_host_by_ip(session: AsyncSession, ip: str) -> Host | None:
    result = await session.execute(
        select(Host).where(Host.ip == ip).options(*_SNAPSHOT_LOADERS)
    )
    return result.scalars().first()


async def fetch_cve(session: AsyncSession, cve_pk: int) -> CVE | None:
    result = await session.execute(
        select(CVE)
        .where(CVE.id == cve_pk)
        .options(selectinload(CVE.port).selectinload(Port.host))
    )
    return result.scalars().first()


async def fetch_port(session: AsyncSession, port_pk: int) -> Port | None:
    result = await session.execute(
        select(Port)
        .where(Port.id == port_pk)
        .options(selectinload(Port.host), selectinload(Port.cves))
    )
    return result.scalars().first()
