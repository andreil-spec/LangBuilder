import json
import os
import time
import uuid
from typing import Any

import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(tags=["OpenAI-Compatible"])

LB_BASE = os.getenv("LANGBUILDER_BASE_URL", "http://127.0.0.1:7860")
LB_TOKEN = os.getenv("LANGBUILDER_TOKEN", "").strip()

MODEL_MAP: dict[str, str] = {}
for pair in filter(None, [p.strip() for p in os.getenv("LB_OPENAI_MODELS", "").split(",")]):
    if "=" in pair:
        k, v = pair.split("=", 1)
        MODEL_MAP[k.strip()] = v.strip()
if not MODEL_MAP:
    # fallback: single flow from LANGBUILDER_FLOW or "default"
    default_flow = os.getenv("LANGBUILDER_FLOW", "default")
    MODEL_MAP = {f"lb:{default_flow}": default_flow}


def _hdr() -> dict[str, str]:
    h = {"Content-Type": "application/json"}
    if LB_TOKEN:
        h["Authorization"] = f"Bearer {LB_TOKEN}"
    return h


# --- Minimal OpenAI schemas we need ---
class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    model: str | None = None
    messages: list[ChatMessage]
    temperature: float | None = 0.2
    stream: bool | None = False
    max_tokens: int | None = None


@router.get("/v1/models")
def list_models():
    return {"object": "list", "data": [{"id": m, "object": "model"} for m in MODEL_MAP]}


def _last_user(msgs: list[ChatMessage]) -> str:
    for m in reversed(msgs):
        if m.role == "user":
            return m.content
    return "\n\n".join(m.content for m in msgs)


def _extract_text(payload: Any) -> str:
    # Walk JSON to find the first string; fallback to JSON dump
    if isinstance(payload, str):
        return payload
    stack = [payload]
    while stack:
        cur = stack.pop()
        if isinstance(cur, str):
            return cur
        if isinstance(cur, dict):
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
    return json.dumps(payload, ensure_ascii=False)


def _run_flow(flow: str, prompt: str) -> Any:
    url = f"{LB_BASE}/api/v1/run/{flow}"
    bodies = [
        {"inputs": {"input": prompt}},
        {"input": prompt},
        {"data": {"input": prompt}},
    ]
    last = None
    for body in bodies:
        try:
            r = requests.post(url, headers=_hdr(), json=body, timeout=60)
            last = r
            if r.ok:
                return r.json()
        except requests.RequestException as e:
            last = e
    if isinstance(last, requests.Response):
        raise HTTPException(status_code=last.status_code, detail=last.text)
    raise HTTPException(status_code=502, detail=f"Flow call failed: {last}")


@router.post("/v1/chat/completions")
def chat(req: ChatRequest):
    model = req.model or next(iter(MODEL_MAP))
    flow = MODEL_MAP.get(model, model)
    prompt = _last_user(req.messages)
    lb_json = _run_flow(flow, prompt)
    text = _extract_text(lb_json)
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }
