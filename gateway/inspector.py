"""
gateway/inspector.py — LLM Response Inspector
================================================

Inspects LLM-generated responses before returning them to the user.

Responsibilities:
1. Placeholder Integrity:
   - Check if placeholders in the response match valid vault entries.
   - Detect corrupted/truncated placeholders (e.g., "PERSON_" without index).
   - Detect hallucinated placeholders (e.g., "PERSON_99" when only 1 exists).

2. Sensitive Information Re-Scan:
   - Run PII detection on the LLM's raw response.
   - Catch cases where the LLM generated NEW sensitive data (hallucinated SSNs,
     credit cards, etc.) not present in the user prompt.

3. Restoration Decision:
   - Decide whether each placeholder is safe to restore.
   - Safe: placeholder exists in vault and matches the expected entity type.
   - Unsafe: corrupted, hallucinated, or response flagged as high-risk.

Usage:
    inspector = ResponseInspector(detector, vault)
    report = inspector.inspect(
        llm_response="Hello PERSON_1, your email is EMAIL_1",
        session_id="s1",
    )
    if report.is_safe:
        restored = transformer.restore(llm_response, session_id,
                                       report.safe_placeholders)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from gateway.detector import PIIDetector, DetectionResult
from gateway.vault import PIIVault


# ── Inspection Report ────────────────────────────────────────

@dataclass
class InspectionReport:
    """Detailed results of inspecting an LLM response."""

    is_safe: bool
    placeholders_found: list[str]
    valid_placeholders: list[str]
    hallucinated_placeholders: list[str]
    corrupted_placeholders: list[str]
    new_pii_detected: list[str]          # Entity types of NEW PII the LLM generated
    new_pii_count: int
    safe_placeholders_to_restore: list[str]
    warnings: list[str]

    @property
    def has_issues(self) -> bool:
        return bool(
            self.hallucinated_placeholders
            or self.corrupted_placeholders
            or self.new_pii_detected
        )

    def get_audit_summary(self) -> dict:
        """Safe-to-log summary of inspection results (no PII values)."""
        return {
            "is_safe": self.is_safe,
            "placeholders_found": len(self.placeholders_found),
            "valid": len(self.valid_placeholders),
            "hallucinated": len(self.hallucinated_placeholders),
            "corrupted": len(self.corrupted_placeholders),
            "new_pii_count": self.new_pii_count,
            "new_pii_types": list(set(self.new_pii_detected)),
            "warnings_count": len(self.warnings),
        }


# ── Regex Patterns ───────────────────────────────────────────

# Matches valid placeholders like PERSON_1, EMAIL_ADDRESS_2, LOCATION_10
PLACEHOLDER_PATTERN = re.compile(r"\b([A-Z][A-Z_]+_\d+)\b")

# Matches corrupted/truncated placeholders like PERSON_ or _1
CORRUPTED_PATTERN = re.compile(
    r"\b([A-Z][A-Z_]+_)(?!\d)\b"  # Type name with underscore but no number
)


# ── Response Inspector ───────────────────────────────────────

class ResponseInspector:
    """
    Validates LLM responses for placeholder integrity and new sensitive info.

    Parameters
    ----------
    detector : PIIDetector
        PII detector for re-scanning LLM output.
    vault : PIIVault
        Vault for verifying placeholder validity against stored mappings.
    """

    def __init__(self, detector: PIIDetector, vault: PIIVault):
        self._detector = detector
        self._vault = vault

    def inspect(
        self,
        llm_response: str,
        session_id: str,
    ) -> InspectionReport:
        """
        Inspect an LLM response for placeholder integrity and new PII.

        Parameters
        ----------
        llm_response : str
            The raw text returned by the LLM.
        session_id : str
            Session ID for vault lookup.

        Returns
        -------
        InspectionReport
            Full inspection breakdown with restoration recommendations.
        """
        if not llm_response or not llm_response.strip():
            return InspectionReport(
                is_safe=True,
                placeholders_found=[],
                valid_placeholders=[],
                hallucinated_placeholders=[],
                corrupted_placeholders=[],
                new_pii_detected=[],
                new_pii_count=0,
                safe_placeholders_to_restore=[],
                warnings=[],
            )

        warnings: list[str] = []

        # ── Step 1: Extract placeholders from response ────────
        found_placeholders = PLACEHOLDER_PATTERN.findall(llm_response)
        # Deduplicate while preserving order
        unique_placeholders = list(dict.fromkeys(found_placeholders))

        # Check for corrupted placeholders
        corrupted = CORRUPTED_PATTERN.findall(llm_response)
        if corrupted:
            warnings.append(
                f"Found {len(corrupted)} corrupted placeholder pattern(s): {corrupted}"
            )

        # ── Step 2: Validate placeholders against vault ───────
        session_mappings = self._vault.get_all_mappings(session_id)
        valid_vault_placeholders = {m["placeholder"] for m in session_mappings}

        valid: list[str] = []
        hallucinated: list[str] = []

        for ph in unique_placeholders:
            if ph in valid_vault_placeholders:
                valid.append(ph)
            else:
                hallucinated.append(ph)
                warnings.append(
                    f"Hallucinated placeholder detected: {ph} (not in vault)"
                )

        # ── Step 3: Scan for NEW PII in LLM output ───────────
        # Replace valid placeholders with dummy text before scanning
        # so Presidio doesn't trip on the placeholder text itself
        masked_for_scan = llm_response
        for ph in valid:
            masked_for_scan = masked_for_scan.replace(ph, "REDACTED")

        response_detections = self._detector.detect(masked_for_scan)

        # Filter out detections that match known original values
        # (in case the LLM somehow produced the exact same name independently)
        known_originals = {
            m["original_value"].lower().strip() for m in session_mappings
        }

        new_pii_types: list[str] = []
        for d in response_detections:
            if d.text.lower().strip() not in known_originals:
                # This is truly NEW sensitive data the LLM generated
                # Ignore low-confidence or generic detections like DATE_TIME
                if d.entity_type not in ("DATE_TIME",) and d.score >= 0.7:
                    new_pii_types.append(d.entity_type)
                    warnings.append(
                        f"LLM generated new {d.entity_type} (score={d.score:.2f})"
                    )

        # ── Step 4: Determine safety and restoration plan ─────
        # A response is safe if:
        # - No corrupted placeholders
        # - No hallucinated placeholders
        # - No high-risk new PII generated
        is_safe = (
            len(hallucinated) == 0
            and len(corrupted) == 0
            and len(new_pii_types) == 0
        )

        # Only restore placeholders that are confirmed valid
        safe_to_restore = valid if is_safe else []

        # If not safe, we might still do partial restoration of valid ones
        # while keeping problematic parts flagged
        if not is_safe and valid:
            # For moderate issues (e.g. only hallucinated, no new PII),
            # we can still safely restore the VALID placeholders
            if len(new_pii_types) == 0:
                safe_to_restore = valid
                warnings.append(
                    "Partial restoration: restoring valid placeholders despite warnings"
                )

        return InspectionReport(
            is_safe=is_safe,
            placeholders_found=unique_placeholders,
            valid_placeholders=valid,
            hallucinated_placeholders=hallucinated,
            corrupted_placeholders=corrupted,
            new_pii_detected=new_pii_types,
            new_pii_count=len(new_pii_types),
            safe_placeholders_to_restore=safe_to_restore,
            warnings=warnings,
        )

    def __repr__(self) -> str:
        return f"ResponseInspector(detector={self._detector!r}, vault={self._vault!r})"
