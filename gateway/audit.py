"""
gateway/audit.py — Security Audit Logging Module (Phase 5)
============================================================

Responsibilities:
- Record security events (detections, blocks, policy actions).
- Log entity types, counts, and processing latency.
- Track per-session statistics without exposing PII.
- Provide structured audit trail for compliance and debugging.

Security constraints:
- NEVER log raw prompts, PII values, credentials, or mappings.
- Log only entity types, counts, action taken, and timing metadata.
- All entries include timestamp, session_id, and event_type.
"""

