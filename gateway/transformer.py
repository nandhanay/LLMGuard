"""
gateway/transformer.py — Text Sanitization Module
=====================================================

Replaces detected PII entities with indexed placeholders (PERSON_1, EMAIL_1)
and restores them in LLM responses when appropriate.

Key behaviors:
- Consistent placeholders: same entity → same placeholder across turns.
- Overlap handling: when detections overlap, keeps the higher-confidence one.
- Right-to-left replacement: preserves character positions during substitution.
- Case-insensitive matching: "Rahul" and "rahul" → same placeholder.

Usage:
    from gateway.detector import PIIDetector
    from gateway.vault import PIIVault
    from gateway.transformer import TextTransformer

    detector = PIIDetector()
    vault = PIIVault(":memory:")
    transformer = TextTransformer(detector, vault)

    result = transformer.sanitize(
        text="Hi, I'm Rahul Sharma. Email: rahul@test.com",
        session_id="session-123",
    )
    print(result.sanitized_text)
    # → "Hi, I'm PERSON_1. Email: EMAIL_1"
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from gateway.detector import PIIDetector, DetectionResult
from gateway.vault import PIIVault
from gateway.resolver import AliasResolver
from gateway.policy import PolicyEngine, PolicyAction


# ── Sanitization Result ──────────────────────────────────────

@dataclass
class SanitizationResult:
    """Result of sanitizing a text input."""

    original_length: int
    sanitized_text: str
    entities_found: int
    entities_replaced: int
    replacements: list[ReplacementInfo]

    @property
    def had_pii(self) -> bool:
        return self.entities_found > 0

    def get_audit_summary(self) -> dict:
        """Return an audit-safe summary (no PII values)."""
        type_counts: dict[str, int] = {}
        for r in self.replacements:
            type_counts[r.entity_type] = type_counts.get(r.entity_type, 0) + 1
        return {
            "entities_found": self.entities_found,
            "entities_replaced": self.entities_replaced,
            "entity_types": type_counts,
            "original_length": self.original_length,
            "sanitized_length": len(self.sanitized_text),
        }


@dataclass
class ReplacementInfo:
    """Metadata about a single replacement (safe to log — no original value)."""

    entity_type: str
    placeholder: str
    start: int          # position in ORIGINAL text
    end: int            # position in ORIGINAL text
    score: float
    was_existing: bool  # True if placeholder was reused from a prior turn


# ── Text Transformer ─────────────────────────────────────────

class TextTransformer:
    """
    Detects PII in text and replaces entities with session-consistent
    indexed placeholders, coordinating with the vault for storage.

    Parameters
    ----------
    detector : PIIDetector
        The PII detection engine.
    vault : PIIVault
        The session-isolated mapping store.
    """

    def __init__(
        self,
        detector: PIIDetector,
        vault: PIIVault,
        policy: Optional[PolicyEngine] = None,
        resolver: Optional[AliasResolver] = None,
        allowed_entities: Optional[set[str]] = None,
    ):
        self._detector = detector
        self._vault = vault
        self._policy = policy or PolicyEngine("policies/default.yaml")
        self._resolver = resolver if resolver is not None else AliasResolver(vault)
        self._allowed_entities = allowed_entities

    def sanitize(
        self,
        text: str,
        session_id: str,
        turn_number: int = 1,
    ) -> SanitizationResult:
        """
        Detect and replace PII entities in text with placeholders.

        Parameters
        ----------
        text : str
            The raw user input.
        session_id : str
            Session identifier for vault isolation.
        turn_number : int
            Conversation turn number (for tracking disclosure progression).

        Returns
        -------
        SanitizationResult
            Contains the sanitized text and metadata about replacements.
        """
        if not text or not text.strip():
            return SanitizationResult(
                original_length=len(text) if text else 0,
                sanitized_text=text or "",
                entities_found=0,
                entities_replaced=0,
                replacements=[],
            )

        # Step 1: Detect PII entities
        detections = self._detector.detect(text)

        # Step 1.5: Cross-turn session alias resolution
        if self._resolver:
            detections = self._resolver.resolve_session_aliases(
                text=text,
                session_id=session_id,
                existing_detections=detections,
            )

        # Filter out entities that policy specifies to ALLOW
        active_detections = []
        for d in detections:
            if self._allowed_entities and d.entity_type in self._allowed_entities:
                continue
            action = self._policy.get_action(d.entity_type)
            if action != PolicyAction.ALLOW:
                active_detections.append(d)

        if not active_detections:
            return SanitizationResult(
                original_length=len(text),
                sanitized_text=text,
                entities_found=0,
                entities_replaced=0,
                replacements=[],
            )

        # Step 2: Resolve overlapping spans (keep higher confidence)
        resolved = self._resolve_overlaps(active_detections)

        # Step 3: Assign placeholders (reuse existing or create new)
        replacements = self._assign_placeholders(
            resolved, session_id, turn_number
        )

        # Step 4: Replace text right-to-left to preserve positions
        sanitized = self._apply_replacements(text, resolved, replacements)

        return SanitizationResult(
            original_length=len(text),
            sanitized_text=sanitized,
            entities_found=len(active_detections),
            entities_replaced=len(resolved),
            replacements=replacements,
        )

    def restore(
        self,
        text: str,
        session_id: str,
        placeholders_to_restore: Optional[list[str]] = None,
    ) -> str:
        """
        Replace placeholders in text with their original values.

        Parameters
        ----------
        text : str
            Text containing placeholders (e.g., "Hello PERSON_1").
        session_id : str
            Session identifier for vault lookup.
        placeholders_to_restore : list[str] | None
            Specific placeholders to restore. None = restore all found.

        Returns
        -------
        str
            Text with placeholders replaced by original values.
        """
        if not text:
            return text

        # Get all mappings for this session
        mappings = self._vault.get_all_mappings(session_id)

        if not mappings:
            return text

        # Sort by placeholder length descending to avoid partial matches
        # (e.g., replace PERSON_10 before PERSON_1)
        mappings.sort(key=lambda m: len(m["placeholder"]), reverse=True)

        result = text
        for mapping in mappings:
            placeholder = mapping["placeholder"]
            original = mapping["original_value"]

            # If specific placeholders requested, skip others
            if placeholders_to_restore and placeholder not in placeholders_to_restore:
                continue

            result = result.replace(placeholder, original)

        return result

    # ── Internal Methods ─────────────────────────────────────

    @staticmethod
    def _resolve_overlaps(
        detections: list[DetectionResult],
    ) -> list[DetectionResult]:
        """
        Remove overlapping detections, keeping higher-confidence ones.

        Strategy: greedy selection sorted by score descending.
        For each detection, include it only if it doesn't overlap with
        any already-selected detection.
        """
        if len(detections) <= 1:
            return list(detections)

        # Sort by confidence descending (prefer higher scores)
        by_score = sorted(detections, key=lambda d: -d.score)

        selected: list[DetectionResult] = []

        for candidate in by_score:
            # Check if this candidate overlaps with any selected detection
            overlaps = False
            for chosen in selected:
                if candidate.start < chosen.end and candidate.end > chosen.start:
                    overlaps = True
                    break

            if not overlaps:
                selected.append(candidate)

        # Re-sort by position for left-to-right processing
        selected.sort(key=lambda d: d.start)
        return selected

    def _assign_placeholders(
        self,
        detections: list[DetectionResult],
        session_id: str,
        turn_number: int,
    ) -> list[ReplacementInfo]:
        """
        Assign a placeholder to each detection, reusing existing mappings
        for consistency across conversation turns.
        """
        replacements: list[ReplacementInfo] = []

        for det in detections:
            action = self._policy.get_action(det.entity_type)

            # Action: REDACT (non-restorable one-way masking, no vault storage)
            if action == PolicyAction.REDACT:
                replacements.append(
                    ReplacementInfo(
                        entity_type=det.entity_type,
                        placeholder=f"[REDACTED_{det.entity_type}]",
                        start=det.start,
                        end=det.end,
                        score=det.score,
                        was_existing=False,
                    )
                )
                continue

            # Action: GENERALIZE (broader k-anonymity bucket, no vault storage)
            if action == PolicyAction.GENERALIZE:
                gen_text = self._policy.generalize_text(det.entity_type, det.text)
                replacements.append(
                    ReplacementInfo(
                        entity_type=det.entity_type,
                        placeholder=gen_text,
                        start=det.start,
                        end=det.end,
                        score=det.score,
                        was_existing=False,
                    )
                )
                continue

            # Action: PSEUDONYMIZE (indexed placeholders + vault mapping)
            existing = self._vault.get_placeholder(session_id, det.text)
            if not existing:
                # Also check if it matches a known session alias
                existing = self._vault.get_alias_placeholder(session_id, det.text)

            if existing:
                # Reuse the existing placeholder
                replacements.append(
                    ReplacementInfo(
                        entity_type=det.entity_type,
                        placeholder=existing,
                        start=det.start,
                        end=det.end,
                        score=det.score,
                        was_existing=True,
                    )
                )
            else:
                # Create a new placeholder
                index = self._vault.get_next_index(session_id, det.entity_type)
                placeholder = f"{det.entity_type}_{index}"

                # Store in vault
                self._vault.store(
                    session_id=session_id,
                    entity_type=det.entity_type,
                    placeholder=placeholder,
                    original_value=det.text,
                    turn_number=turn_number,
                )

                # Register aliases for future turns
                if self._resolver:
                    self._resolver.register_aliases(
                        session_id=session_id,
                        entity_type=det.entity_type,
                        canonical_value=det.text,
                        placeholder=placeholder,
                    )

                replacements.append(
                    ReplacementInfo(
                        entity_type=det.entity_type,
                        placeholder=placeholder,
                        start=det.start,
                        end=det.end,
                        score=det.score,
                        was_existing=False,
                    )
                )

        return replacements

    @staticmethod
    def _apply_replacements(
        text: str,
        detections: list[DetectionResult],
        replacements: list[ReplacementInfo],
    ) -> str:
        """
        Apply replacements right-to-left to preserve character positions.
        """
        # Pair detections with their replacements, sorted by start position descending
        pairs = list(zip(detections, replacements))
        pairs.sort(key=lambda p: p[0].start, reverse=True)

        result = text
        for detection, replacement in pairs:
            result = (
                result[: detection.start]
                + replacement.placeholder
                + result[detection.end :]
            )

        return result

    def __repr__(self) -> str:
        return f"TextTransformer(detector={self._detector!r}, vault={self._vault!r})"
