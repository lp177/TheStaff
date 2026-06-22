"""Optional operator authentication for mutating / active-scan endpoints.

If THESTAFF_ADMIN_TOKEN is set, those endpoints require a matching
X-Admin-Token header. If it's unset, the API stays open — convenient for dev
and small trusted setups — and we log a one-time warning so operators know.
Read-only endpoints (hosts/status) and the participant consent POST stay open.
"""

from __future__ import annotations

import logging
import secrets

from fastapi import Header, HTTPException

from .config import settings

log = logging.getLogger("thestaff.auth")
_warned = False


async def require_operator(x_admin_token: str | None = Header(default=None)) -> None:
    global _warned
    if not settings.admin_token:
        if not _warned:
            log.warning(
                "THESTAFF_ADMIN_TOKEN not set — mutating endpoints are OPEN. "
                "Set it to require an operator token at public events."
            )
            _warned = True
        return
    if not x_admin_token or not secrets.compare_digest(x_admin_token, settings.admin_token):
        raise HTTPException(status_code=401, detail="operator token required")
