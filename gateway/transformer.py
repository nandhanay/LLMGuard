"""
gateway/transformer.py — Sanitization / Transformation Module (Phase 3)
========================================================================

Responsibilities:
- Replace detected PII entities with indexed placeholders (PERSON_1, EMAIL_1).
- Maintain consistent placeholder assignment within a session.
- Handle overlapping detection spans by prioritizing higher-confidence matches.
- Coordinate with vault.py to store original-to-placeholder mappings.
- Support future GENERALIZE action (e.g., exact age → age range).

This module transforms raw text into a privacy-safe version suitable for LLM input.
"""

