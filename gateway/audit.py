"""
gateway/audit.py — Security Audit Logging Module
===================================================

Records security events in structured JSON-Lines format.

Strict Privacy Guarantees:
- NEVER logs raw prompts or LLM responses.
- NEVER logs raw PII values or vault mappings.
- Logs ONLY: timestamps, session IDs, turn numbers, entity types,
  counts, processing latency, and inspection safety decisions.

Usage:
    from gateway.audit import AuditLogger

    audit = AuditLogger("logs/audit.jsonl")
    audit.log_event(
        event_type="chat_turn",
        session_id="s1",
        data={
            "turn": 1,
            "entities_found": 2,
            "entity_types": {"PERSON": 1, "EMAIL_ADDRESS": 1},
            "processing_time_ms": 145.2,
            "is_safe": True,
        }
    )
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


class AuditLogger:
    """
    Thread-safe structured audit logger writing JSON lines.
    Ensures no PII is ever recorded.
    """

    # Disallowed keys to prevent accidental PII leakage in audit data
    FORBIDDEN_KEYS = {
        "text", "prompt", "message", "reply", "response",
        "original_value", "pii", "mapping", "mappings", "raw"
    }

    def __init__(self, log_path: str | Path = "logs/audit.jsonl"):
        self.log_path = Path(log_path)
        self._lock = threading.Lock()
        if self.log_path != Path(":memory:"):
            self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log_event(
        self,
        event_type: str,
        session_id: str,
        data: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Record an audit event.

        Parameters
        ----------
        event_type : str
            Event classification (e.g. 'chat_turn', 'pii_detected', 'session_cleared').
        session_id : str
            Identifier of the session.
        data : dict | None
            Metadata about the event (counts, latency, entity types).
        """
        payload = data or {}

        # Safety check: reject any keys that could hold raw content
        for key in payload:
            if key.lower() in self.FORBIDDEN_KEYS:
                raise ValueError(
                    f"Audit security violation: key '{key}' is forbidden in audit logs."
                )

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "session_id": session_id,
            **payload,
        }

        if self.log_path != Path(":memory:"):
            line = json.dumps(record) + "\n"
            with self._lock:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line)

        return record

    def read_events(self, session_id: Optional[str] = None) -> list[dict[str, Any]]:
        """Read recorded audit events (optionally filtered by session)."""
        if self.log_path == Path(":memory:") or not self.log_path.exists():
            return []

        events = []
        with self._lock:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                        if session_id is None or record.get("session_id") == session_id:
                            events.append(record)
                    except json.JSONDecodeError:
                        continue
        return events
