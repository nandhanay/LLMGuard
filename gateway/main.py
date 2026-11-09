"""
gateway/main.py — FastAPI Application Entry Point (Phase 4)
=============================================================

Responsibilities:
- Define the FastAPI app and the POST /chat endpoint.
- Accept { session_id, message } from the user.
- Orchestrate the full pipeline:
    1. Detect PII (detector.py)
    2. Apply policy (policy.py — simple pseudonymize in v1)
    3. Sanitize text (transformer.py)
    4. Store mappings (vault.py)
    5. Forward sanitized text to Ollama (HTTP API)
    6. Inspect LLM response (inspector.py)
    7. Restore placeholders if safe
    8. Log audit event (audit.py)
- Return the final response to the user.

Never send unsanitized text to the LLM.
"""

