"""HTTP routers for thestaff."""

from fastapi import APIRouter

from . import ai, consent, hosts, remediation

api_router = APIRouter()
api_router.include_router(hosts.router, tags=["hosts"])
api_router.include_router(remediation.router, tags=["remediation"])
api_router.include_router(consent.router, tags=["consent"])
api_router.include_router(ai.router, tags=["ai"])
