"""
Policy Intelligence LLM Server.

A lightweight FastAPI server that proxies chat requests to Azure OpenAI,
providing natural-language policy explanations and Z3 result interpretation
for the web-demo frontend.

Start:
    cd examples/web-demo/llm-server
    pip install -r requirements.txt
    uvicorn server:app --port 8000 --reload
"""

from __future__ import annotations

import json
import logging
import uuid

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

import llm_client
from schemas import ChatRequest, ChatResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── App ─────────────────────────────────────────────────────────────────────

app = FastAPI(title="Policy Intelligence LLM Server", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8080",
        "http://127.0.0.1:8080",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-memory session store ─────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a policy analysis assistant for the Policy Intelligence demo.

You help users understand Rego, Cedar, and Azure Policy definitions.
You can:
  - Explain policy logic, rule interactions, and edge cases.
  - Interpret Z3 SMT solver results — these are concrete inputs synthesized
    by the solver that satisfy or violate the policy under analysis.
  - Suggest policy improvements or point out potential issues.

When the user provides analysis context (policy text, Z3 results, schemas),
ground your answers in that context.  Be concise and precise.
Use short code snippets when they clarify your explanation.\
"""

# session_id → list of {"role": ..., "content": ...}
_sessions: dict[str, list[dict[str, str]]] = {}


def _get_or_create_session(
    session_id: str | None,
) -> tuple[str, list[dict[str, str]]]:
    sid = session_id or str(uuid.uuid4())
    if sid not in _sessions:
        _sessions[sid] = [{"role": "system", "content": SYSTEM_PROMPT}]
    return sid, _sessions[sid]


def _build_context_block(context: dict | None) -> str:
    """Format optional context (policy text, analysis result, schema) for the LLM."""
    if not context:
        return ""
    parts: list[str] = []
    if context.get("policy"):
        parts.append(f"## Policy\n```\n{context['policy']}\n```")
    if context.get("schema"):
        schema = context["schema"]
        if isinstance(schema, dict):
            schema = json.dumps(schema, indent=2)
        parts.append(f"## Input Schema\n```json\n{schema}\n```")
    if context.get("analysis_result"):
        result = context["analysis_result"]
        if isinstance(result, dict):
            result = json.dumps(result, indent=2)
        parts.append(f"## Z3 Analysis Result\n```json\n{result}\n```")
    if context.get("smt"):
        parts.append(f"## SMT-LIB2 Constraints\n```smt2\n{context['smt']}\n```")
    return "\n\n".join(parts)


# ── Endpoints ───────────────────────────────────────────────────────────────


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/chat", response_model=ChatResponse)
async def chat(body: ChatRequest):
    sid, messages = _get_or_create_session(body.session_id)

    # If context is provided, inject it as a system-level context message
    # right before the user message so the LLM sees it fresh each turn.
    ctx_text = _build_context_block(body.context)
    if ctx_text:
        messages.append({"role": "system", "content": ctx_text})

    messages.append({"role": "user", "content": body.message})

    reply = await llm_client.chat(messages)

    messages.append({"role": "assistant", "content": reply})

    return ChatResponse(session_id=sid, reply=reply)


@app.post("/api/chat/stream")
async def chat_stream(body: ChatRequest):
    sid, messages = _get_or_create_session(body.session_id)

    ctx_text = _build_context_block(body.context)
    if ctx_text:
        messages.append({"role": "system", "content": ctx_text})

    messages.append({"role": "user", "content": body.message})

    async def event_generator():
        full_reply: list[str] = []
        async for chunk in llm_client.chat_stream(messages):
            full_reply.append(chunk)
            # SSE frame: one data line per chunk
            payload = json.dumps({"chunk": chunk}, ensure_ascii=False)
            yield f"data: {payload}\n\n"

        # Persist the full reply in session history
        messages.append({"role": "assistant", "content": "".join(full_reply)})

        # Signal completion
        done = json.dumps(
            {"done": True, "session_id": sid}, ensure_ascii=False
        )
        yield f"data: {done}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/sessions")
def list_sessions():
    return {
        "sessions": [
            {
                "session_id": sid,
                "message_count": len(
                    [m for m in msgs if m["role"] == "user"]
                ),
            }
            for sid, msgs in _sessions.items()
        ]
    }


@app.delete("/api/sessions/{session_id}")
def delete_session(session_id: str):
    deleted = _sessions.pop(session_id, None) is not None
    return {"deleted": deleted, "session_id": session_id}
