"""Optional LLM proxy for the operator's "Ask AI about this CVE" helper.

The browser holds the API key (localStorage) and sends it per request; we never
persist it. This is the only operator-facing egress beyond the LAN besides the
public-IP lookup, and is gated by THESTAFF_AI_PROXY. A proxy (not direct browser
calls) is required because OpenAI does not allow cross-origin browser requests.
Uses stdlib urllib — no provider SDKs, keeping the container lean.
"""

from __future__ import annotations

import asyncio
import json
import logging
import urllib.error
import urllib.request

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..auth import require_operator
from ..config import settings

log = logging.getLogger("thestaff.ai")
router = APIRouter()

ANTHROPIC_VERSION = "2023-06-01"
_PROVIDERS = ("anthropic", "openai")
# OpenAI's /models lists everything; keep only chat-capable families.
_OPENAI_KEEP = ("gpt-", "o1", "o3", "o4", "chatgpt")
# 'instruct' models are completions-only and 400 on /chat/completions; the rest
# are non-chat modalities. ('search' is intentionally NOT dropped — e.g.
# gpt-4o-search-preview is a valid chat model.)
_OPENAI_DROP = ("embedding", "whisper", "tts", "dall-e", "moderation", "audio",
                "realtime", "image", "transcribe", "davinci", "babbage", "instruct")


class ModelsBody(BaseModel):
    provider: str
    key: str


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatBody(BaseModel):
    provider: str
    model: str
    key: str
    messages: list[ChatMessage]
    system: str | None = None


def _http_json(method: str, url: str, headers: dict, body: dict | None = None,
               timeout: float = 60.0) -> tuple[int, dict]:
    """Blocking JSON request. Returns (status, parsed) where parsed may hold an
    'error' key on transport/HTTP failure. Never raises."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return resp.status, json.loads(resp.read().decode("utf-8", "ignore") or "{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "ignore")
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {"error": raw[:500]}
    except Exception as exc:  # noqa: BLE001
        return 0, {"error": str(exc)}


def _err_message(data: dict) -> str:
    e = data.get("error") if isinstance(data, dict) else None
    if isinstance(e, dict):
        return str(e.get("message") or e.get("type") or json.dumps(e)[:300])
    if isinstance(e, str):
        return e[:300]
    return "upstream provider error"


def _guard(provider: str, key: str) -> None:
    if not settings.ai_proxy:
        raise HTTPException(status_code=403, detail="AI assistant disabled (THESTAFF_AI_PROXY=0)")
    if provider not in _PROVIDERS:
        raise HTTPException(status_code=400, detail=f"unknown provider {provider!r}")
    if not key.strip():
        raise HTTPException(status_code=400, detail="missing API key")


# ---- model discovery -------------------------------------------------------
def _discover(provider: str, key: str) -> tuple[int, dict]:
    if provider == "anthropic":
        status, data = _http_json(
            "GET", "https://api.anthropic.com/v1/models",
            {"x-api-key": key, "anthropic-version": ANTHROPIC_VERSION}, timeout=20)
        if status != 200:
            return status, data
        models = [{"id": m["id"], "label": m.get("display_name") or m["id"]}
                  for m in data.get("data", []) if m.get("id")]
        return 200, {"models": models}

    status, data = _http_json(
        "GET", "https://api.openai.com/v1/models",
        {"Authorization": f"Bearer {key}"}, timeout=20)
    if status != 200:
        return status, data
    models = []
    for m in data.get("data", []):
        mid = (m.get("id") or "")
        low = mid.lower()
        if any(b in low for b in _OPENAI_DROP):
            continue
        if low.startswith(_OPENAI_KEEP):
            models.append({"id": mid, "label": mid})
    models.sort(key=lambda x: x["id"])
    return 200, {"models": models}


@router.post("/ai/models", dependencies=[Depends(require_operator)])
async def ai_models(body: ModelsBody) -> dict:
    _guard(body.provider, body.key)
    loop = asyncio.get_running_loop()
    status, data = await loop.run_in_executor(
        None, _discover, body.provider, body.key.strip())
    if status != 200:
        raise HTTPException(status_code=502, detail=_err_message(data))
    log.info("ai: discovered %d %s models", len(data.get("models", [])), body.provider)
    return data


# ---- chat completion -------------------------------------------------------
def _chat(provider: str, model: str, key: str,
          messages: list[dict], system: str | None) -> tuple[int, dict]:
    if provider == "anthropic":
        payload = {"model": model, "max_tokens": 4096,
                   "messages": [{"role": m["role"], "content": m["content"]} for m in messages]}
        if system:
            payload["system"] = system
        status, data = _http_json(
            "POST", "https://api.anthropic.com/v1/messages",
            {"x-api-key": key, "anthropic-version": ANTHROPIC_VERSION,
             "content-type": "application/json"}, payload, timeout=120)
        if status != 200:
            return status, data
        text = "".join(b.get("text", "") for b in data.get("content", [])
                       if b.get("type") == "text")
        return 200, {"content": text}

    msgs = ([{"role": "system", "content": system}] if system else []) + \
           [{"role": m["role"], "content": m["content"]} for m in messages]
    status, data = _http_json(
        "POST", "https://api.openai.com/v1/chat/completions",
        {"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        {"model": model, "messages": msgs}, timeout=120)
    if status != 200:
        return status, data
    choices = data.get("choices") or [{}]
    # `content` can be JSON null; coerce to "" to match the Anthropic branch.
    return 200, {"content": choices[0].get("message", {}).get("content") or ""}


@router.post("/ai/chat", dependencies=[Depends(require_operator)])
async def ai_chat(body: ChatBody) -> dict:
    _guard(body.provider, body.key)
    if not body.model.strip():
        raise HTTPException(status_code=400, detail="missing model")
    if not body.messages:
        raise HTTPException(status_code=400, detail="no messages")
    loop = asyncio.get_running_loop()
    status, data = await loop.run_in_executor(
        None, _chat, body.provider, body.model.strip(), body.key.strip(),
        [m.model_dump() for m in body.messages], body.system)
    if status != 200:
        raise HTTPException(status_code=502, detail=_err_message(data))
    return data
