"""
gateway/main.py — FastAPI Privacy Gateway
============================================

Entry point for the LLM Privacy Gateway. Provides:
  - POST /chat       — Send a message through the privacy pipeline
  - GET  /health     — Health check (dependencies status)
  - DELETE /session   — Wipe a session's vault data

Pipeline:
  1. Detect PII (detector.py)
  2. Sanitize text with placeholders (transformer.py)
  3. Store mappings in session-isolated vault (vault.py)
  4. Send ONLY sanitized text to Ollama
  5. Restore placeholders in response (if safe)
  6. Return response to user

Never sends raw/unsanitized prompts to the LLM.
"""

from __future__ import annotations

import time
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from gateway.detector import PIIDetector
from gateway.vault import PIIVault
from gateway.transformer import TextTransformer
from gateway.inspector import ResponseInspector
from gateway.audit import AuditLogger

# ── Logging (never logs PII) ─────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("gateway")

# ── Configuration ─────────────────────────────────────────────

OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_MODEL = "llama3.2:3b"
DB_PATH = Path("privacy_vault.db")
SCORE_THRESHOLD = 0.7
OLLAMA_TIMEOUT = 120.0  # seconds — LLM can be slow on CPU

# ── Conversation History (sanitized only) ─────────────────────
# In-memory store of sanitized messages per session.
# Only sanitized text is stored — never raw user input.
_session_histories: dict[str, list[dict[str, str]]] = {}

MAX_HISTORY_TURNS = 20  # Keep last N messages per session


# ── Request / Response Models ─────────────────────────────────

class ChatRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=128,
                            description="Session identifier")
    message: str = Field(..., min_length=1, max_length=10000,
                         description="User message")


class ChatResponse(BaseModel):
    session_id: str
    reply: str
    pii_detected: bool
    entities_found: int
    processing_time_ms: float


class HealthResponse(BaseModel):
    status: str
    ollama_reachable: bool
    ollama_model: str
    vault_initialized: bool
    detector_ready: bool


class SessionDeleteResponse(BaseModel):
    session_id: str
    mappings_deleted: int
    history_cleared: bool


# ── Application Lifespan ──────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and clean up shared resources."""
    logger.info("Initializing Privacy Gateway...")

    # Initialize components
    app.state.detector = PIIDetector(score_threshold=SCORE_THRESHOLD)
    app.state.vault = PIIVault(str(DB_PATH))
    app.state.transformer = TextTransformer(
        app.state.detector, app.state.vault
    )
    app.state.inspector = ResponseInspector(
        app.state.detector, app.state.vault
    )
    app.state.audit_logger = AuditLogger()
    app.state.http_client = httpx.AsyncClient(
        base_url=OLLAMA_BASE_URL,
        timeout=OLLAMA_TIMEOUT,
    )

    logger.info("Detector ready (threshold=%.2f)", SCORE_THRESHOLD)
    logger.info("Vault initialized at %s", DB_PATH)
    logger.info("Ollama target: %s (model=%s)", OLLAMA_BASE_URL, OLLAMA_MODEL)
    logger.info("Privacy Gateway started.")

    yield

    # Cleanup
    logger.info("Shutting down...")
    await app.state.http_client.aclose()
    app.state.vault.close()
    logger.info("Shutdown complete.")


# ── FastAPI App ───────────────────────────────────────────────

app = FastAPI(
    title="LLMGuard Privacy Gateway",
    description="Privacy-aware proxy for LLM interactions with PII detection and sanitization.",
    version="0.1.0",
    lifespan=lifespan,
)


# ── POST /chat ────────────────────────────────────────────────

@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Process a user message through the privacy pipeline.

    1. Detect PII in the message
    2. Replace PII with session-consistent placeholders
    3. Send sanitized message to Ollama
    4. Restore placeholders in the response
    5. Return the final response
    """
    t_start = time.perf_counter()

    transformer: TextTransformer = app.state.transformer
    http_client: httpx.AsyncClient = app.state.http_client

    session_id = request.session_id
    raw_message = request.message

    # ── Step 1+2: Detect & Sanitize ───────────────────────────
    turn_number = len(_session_histories.get(session_id, [])) // 2 + 1

    sanitization = transformer.sanitize(
        text=raw_message,
        session_id=session_id,
        turn_number=turn_number,
    )

    sanitized_message = sanitization.sanitized_text

    # Log audit-safe summary (never raw PII)
    audit = sanitization.get_audit_summary()
    logger.info(
        "session=%s turn=%d entities=%d types=%s",
        session_id, turn_number, audit["entities_found"], audit["entity_types"],
    )

    # ── Step 3: Build conversation history (sanitized only) ───
    if session_id not in _session_histories:
        _session_histories[session_id] = []

    history = _session_histories[session_id]

    # Add sanitized user message to history
    history.append({"role": "user", "content": sanitized_message})

    # Trim history to max turns
    if len(history) > MAX_HISTORY_TURNS:
        history[:] = history[-MAX_HISTORY_TURNS:]

    # ── Step 4: Send to Ollama ────────────────────────────────
    ollama_payload = {
        "model": OLLAMA_MODEL,
        "messages": list(history),  # Only sanitized messages
        "stream": False,
    }

    try:
        response = await http_client.post(
            "/api/chat",
            json=ollama_payload,
        )
        response.raise_for_status()
        ollama_data = response.json()
    except httpx.ConnectError:
        raise HTTPException(
            status_code=503,
            detail="Cannot connect to Ollama. Is it running at "
                   f"{OLLAMA_BASE_URL}?",
        )
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail=f"Ollama did not respond within {OLLAMA_TIMEOUT}s.",
        )
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Ollama returned error: {e.response.status_code}",
        )

    llm_reply = ollama_data.get("message", {}).get("content", "")

    # Store sanitized assistant response in history
    history.append({"role": "assistant", "content": llm_reply})

    # ── Step 5: Inspect response & restore placeholders ────────
    inspector: Optional[ResponseInspector] = getattr(app.state, "inspector", None)
    if inspector:
        inspection = inspector.inspect(llm_reply, session_id=session_id)
        restored_reply = transformer.restore(
            llm_reply,
            session_id=session_id,
            placeholders_to_restore=inspection.safe_placeholders_to_restore,
        )
    else:
        restored_reply = transformer.restore(llm_reply, session_id=session_id)
        inspection = None

    # ── Step 6: Log audit event (safe, no raw PII) ────────────
    elapsed_ms = (time.perf_counter() - t_start) * 1000

    audit_logger: Optional[AuditLogger] = getattr(app.state, "audit_logger", None)
    if audit_logger:
        audit_logger.log_event(
            event_type="chat_turn",
            session_id=session_id,
            data={
                "turn": turn_number,
                "entities_found": sanitization.entities_found,
                "entities_replaced": sanitization.entities_replaced,
                "entity_types": audit["entity_types"],
                "processing_time_ms": round(elapsed_ms, 1),
                "is_safe": inspection.is_safe if inspection else True,
            },
        )

    # ── Step 7: Return response ───────────────────────────────

    logger.info(
        "session=%s turn=%d completed in %.0fms",
        session_id, turn_number, elapsed_ms,
    )

    return ChatResponse(
        session_id=session_id,
        reply=restored_reply,
        pii_detected=sanitization.had_pii,
        entities_found=sanitization.entities_found,
        processing_time_ms=round(elapsed_ms, 1),
    )


# ── GET /health ───────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse)
async def health():
    """Check the status of all dependencies."""
    http_client: httpx.AsyncClient = app.state.http_client

    # Check Ollama
    ollama_ok = False
    try:
        resp = await http_client.get("/api/tags", timeout=5.0)
        ollama_ok = resp.status_code == 200
    except Exception:
        pass

    return HealthResponse(
        status="ok" if ollama_ok else "degraded",
        ollama_reachable=ollama_ok,
        ollama_model=OLLAMA_MODEL,
        vault_initialized=True,
        detector_ready=True,
    )


# ── DELETE /session ───────────────────────────────────────────

@app.delete("/session/{session_id}", response_model=SessionDeleteResponse)
async def delete_session(session_id: str):
    """Delete all vault mappings and conversation history for a session."""
    vault: PIIVault = app.state.vault

    deleted = vault.delete_session(session_id)
    history_existed = session_id in _session_histories
    _session_histories.pop(session_id, None)

    logger.info("session=%s deleted mappings=%d history=%s",
                session_id, deleted, history_existed)

    return SessionDeleteResponse(
        session_id=session_id,
        mappings_deleted=deleted,
        history_cleared=history_existed,
    )
