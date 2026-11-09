"""
gateway/vault.py — Secure PII Vault (Phase 3)
===============================================

Responsibilities:
- Store original-to-placeholder mappings in SQLite.
- Isolate data by session_id — no cross-session access.
- Support lookup in both directions (original → placeholder, placeholder → original).
- Maintain mapping consistency across conversation turns.
- Provide secure restoration of placeholders in LLM responses when appropriate.

Security constraints:
- Mappings are never logged.
- Sessions cannot enumerate or access other sessions' data.
- The vault is the ONLY component that holds raw PII values.
"""

