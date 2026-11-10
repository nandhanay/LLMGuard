"""
gateway/resolver.py — Alias Resolution & Entity Graph Module
===============================================================

Maintains cross-turn entity consistency by:
1. Extracting aliases when an entity is first registered
   (e.g., "Arunima Sen" -> first name "Arunima", surname "Sen", "Ms. Sen").
2. Scanning subsequent conversation turns for known session aliases
   (even if statistical NER models miss isolated single-word names).
3. Mapping all aliases to the identical canonical placeholder
   (e.g., both "Arunima Sen" and "Arunima" map to PERSON_1).

This addresses indirect disclosure and alias leakage across multi-turn chats.
"""

from __future__ import annotations

import re
from typing import Optional

from gateway.detector import DetectionResult
from gateway.vault import PIIVault


class AliasResolver:
    """
    Session-aware alias resolution engine.
    """

    HONORIFICS = ["Mr.", "Ms.", "Mrs.", "Dr.", "Prof.", "Shri", "Smt."]

    def __init__(self, vault: PIIVault):
        self._vault = vault

    def extract_aliases(self, entity_type: str, canonical_value: str) -> list[str]:
        """
        Derive aliases from a canonical entity name.

        Examples
        --------
        - "Arunima Sen" -> ["Arunima", "Sen"]
        - "Dr. Vikram Deshmukh" -> ["Vikram", "Deshmukh", "Dr. Deshmukh"]
        - "Avi Gupta" -> ["Avi", "Gupta"]
        """
        aliases: list[str] = []
        if entity_type == "PERSON":
            cleaned = canonical_value.strip()
            honorific = None
            for title in self.HONORIFICS:
                if cleaned.startswith(title + " "):
                    honorific = title
                    cleaned = cleaned[len(title) + 1:].strip()
                    break

            parts = cleaned.split()
            if len(parts) >= 2:
                first_name = parts[0]
                last_name = parts[-1]
                # Keep names of length >= 3 to avoid matching random initials
                if len(first_name) >= 3:
                    aliases.append(first_name)
                if len(last_name) >= 3:
                    aliases.append(last_name)
                if honorific and len(last_name) >= 3:
                    aliases.append(f"{honorific} {last_name}")

        return aliases

    def register_aliases(
        self,
        session_id: str,
        entity_type: str,
        canonical_value: str,
        placeholder: str,
    ) -> list[str]:
        """
        Extract and store aliases in the session vault.
        """
        aliases = self.extract_aliases(entity_type, canonical_value)
        for alias in aliases:
            self._vault.store_alias(
                session_id=session_id,
                entity_type=entity_type,
                alias_value=alias,
                canonical_placeholder=placeholder,
            )
        return aliases

    def resolve_session_aliases(
        self,
        text: str,
        session_id: str,
        existing_detections: list[DetectionResult],
    ) -> list[DetectionResult]:
        """
        Scan text for known session aliases that were not detected by standard NER.
        Injects high-confidence DetectionResults mapped to the canonical entity type.
        """
        session_aliases = self._vault.get_all_aliases(session_id)
        if not session_aliases:
            return list(existing_detections)

        # Track character spans already covered by detections
        occupied_spans = [(d.start, d.end) for d in existing_detections]
        resolved = list(existing_detections)

        for item in session_aliases:
            alias = item["alias_value"]
            entity_type = item["entity_type"]

            # Exact word-boundary search (case-insensitive)
            pattern = re.compile(rf"\b{re.escape(alias)}\b", re.IGNORECASE)
            for match in pattern.finditer(text):
                start, end = match.span()

                # Verify no overlap with existing detections
                overlaps = any(
                    max(start, o_start) < min(end, o_end)
                    for o_start, o_end in occupied_spans
                )

                if not overlaps:
                    resolved.append(
                        DetectionResult(
                            entity_type=entity_type,
                            text=text[start:end],
                            start=start,
                            end=end,
                            score=0.98,  # Grounded in active session history
                        )
                    )
                    occupied_spans.append((start, end))

        # Re-sort by start index
        resolved.sort(key=lambda d: (d.start, -d.score))
        return resolved
