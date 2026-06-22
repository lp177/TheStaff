"""Consent endpoints powering the honest opt-in page (not a deceptive portal)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from ..config import settings
from ..db import get_session
from ..models import ConsentRecord

router = APIRouter()


class ConsentBody(BaseModel):
    accepted: bool = True


@router.get("/consent")
async def consent_info(session: AsyncSession = Depends(get_session)) -> dict:
    count = await session.scalar(
        select(func.count()).select_from(ConsentRecord).where(ConsentRecord.accepted)
    )
    return {
        "mode": settings.consent_mode,
        "organizer": settings.organizer,
        "organizer_email": settings.organizer_email,
        "ssid": settings.ssid,
        "event": settings.event_name,
        "target_cidr": settings.effective_cidr or settings.target_cidr,
        "opt_in_count": count or 0,
    }


@router.post("/consent")
async def record_consent(body: ConsentBody, request: Request,
                         session: AsyncSession = Depends(get_session)) -> dict:
    record = ConsentRecord(
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        accepted=body.accepted,
    )
    session.add(record)
    await session.commit()
    return {"ok": True}
