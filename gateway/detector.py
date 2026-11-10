"""
gateway/detector.py — PII Detection Module
============================================

Wraps Microsoft Presidio Analyzer to detect PII entities in user text.
Returns structured DetectionResult objects with entity type, matched text,
character positions, and confidence scores.

Supported entities (default):
    PERSON, EMAIL_ADDRESS, PHONE_NUMBER, LOCATION, DATE_TIME,
    CREDIT_CARD, CRYPTO, IBAN_CODE, IP_ADDRESS, MEDICAL_LICENSE,
    URL, NRP (nationality/religion/political group), US_SSN, etc.

Usage:
    from gateway.detector import PIIDetector

    detector = PIIDetector()
    results = detector.detect("My name is Rahul and my email is rahul@test.com")
    for r in results:
        print(f"{r.entity_type}: '{r.text}' (score={r.score:.2f})")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from presidio_analyzer import (
    AnalyzerEngine,
    Pattern,
    PatternRecognizer,
    RecognizerResult,
)


# ── Detection Result ──────────────────────────────────────────

@dataclass(frozen=True)
class DetectionResult:
    """A single detected PII entity with its metadata."""

    entity_type: str       # e.g., "PERSON", "EMAIL_ADDRESS"
    text: str              # The matched substring from the input
    start: int             # Start character index (inclusive)
    end: int               # End character index (exclusive)
    score: float           # Presidio confidence score (0.0–1.0)

    def __repr__(self) -> str:
        return (
            f"DetectionResult(type={self.entity_type!r}, "
            f"text={self.text!r}, span=({self.start},{self.end}), "
            f"score={self.score:.2f})"
        )


# ── Default entity types to detect ───────────────────────────

DEFAULT_ENTITIES: list[str] = [
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "LOCATION",
    "CREDIT_CARD",
    "CRYPTO",
    "IBAN_CODE",
    "IP_ADDRESS",
    "URL",
    "NRP",
    "MEDICAL_LICENSE",
    "US_SSN",
    "US_BANK_NUMBER",
    "US_DRIVER_LICENSE",
    "US_PASSPORT",
    "US_ITIN",
    "IN_PAN",
    "IN_AADHAAR",
]


# ── PII Detector ─────────────────────────────────────────────

class PIIDetector:
    """
    Detects PII entities in text using Microsoft Presidio.

    Parameters
    ----------
    score_threshold : float
        Minimum confidence score to include a detection (default: 0.7).
    entities : list[str] | None
        Entity types to detect. None = DEFAULT_ENTITIES.
    language : str
        Language code for the analyzer (default: "en").
    """

    def __init__(
        self,
        score_threshold: float = 0.7,
        entities: Optional[list[str]] = None,
        language: str = "en",
    ):
        self.score_threshold = score_threshold
        self.entities = entities or DEFAULT_ENTITIES
        self.language = language

        # Initialize the Presidio analyzer engine once.
        # This loads spaCy models internally — can take 1-2 seconds on first call.
        self._engine = AnalyzerEngine()
        self._register_custom_recognizers()

    def _register_custom_recognizers(self) -> None:
        """Register domain-specific recognizers for Indian identifiers and titles."""
        # 1. Indian PAN Card (Permanent Account Number)
        # Format: 5 uppercase letters, 4 digits, 1 uppercase letter (e.g. AADPE7873B)
        pan_pattern = Pattern(
            name="in_pan_pattern",
            regex=r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
            score=0.85,
        )
        pan_recognizer = PatternRecognizer(
            supported_entity="IN_PAN",
            patterns=[pan_pattern],
            context=["pan", "pan card", "tax", "permanent account number", "income tax", "clearance"],
        )
        self._engine.registry.add_recognizer(pan_recognizer)

        # 2. Indian Aadhaar Card
        # Format: 12 digits, often formatted as 4-4-4
        aadhaar_pattern = Pattern(
            name="in_aadhaar_pattern",
            regex=r"\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b",
            score=0.85,
        )
        aadhaar_recognizer = PatternRecognizer(
            supported_entity="IN_AADHAAR",
            patterns=[aadhaar_pattern],
            context=["aadhaar", "aadhar", "uidai", "uid", "identity"],
        )
        self._engine.registry.add_recognizer(aadhaar_recognizer)

        # 3. Enhanced Indian Phone Number Recognizer (+91 prefix & 10-digit formats)
        phone_pattern = Pattern(
            name="in_phone_pattern",
            regex=r"(?:\+91[\-\s]?)?[6-9]\d{4}[\-\s]?\d{5}\b|(?:\+91[\-\s]?)[6-9]\d{9}\b",
            score=0.85,
        )
        in_phone_recognizer = PatternRecognizer(
            supported_entity="PHONE_NUMBER",
            patterns=[phone_pattern],
            context=["phone", "mobile", "cell", "call", "contact", "coordinates"],
        )
        self._engine.registry.add_recognizer(in_phone_recognizer)

        # 4. Formal Indian Honorific Person Names (e.g. Mr. Sharma, Dr. Babu)
        honorific_pattern = Pattern(
            name="in_honorific_name_pattern",
            regex=r"\b(?:Mr\.|Ms\.|Mrs\.|Dr\.|Prof\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b",
            score=0.85,
        )
        honorific_recognizer = PatternRecognizer(
            supported_entity="PERSON",
            patterns=[honorific_pattern],
            context=["name", "contact", "addressing", "behalf of", "advisor", "letter"],
        )
        self._engine.registry.add_recognizer(honorific_recognizer)

        # 5. Role/Context-introduced Person Names (e.g. "tenant listed in draft is Pahal Oak")
        context_name_pattern = Pattern(
            name="in_context_name_pattern",
            regex=r"\b[A-Z][a-z]{1,15}\s+[A-Z][a-z]{1,15}\b",
            score=0.65,
        )
        context_name_recognizer = PatternRecognizer(
            supported_entity="PERSON",
            patterns=[context_name_pattern],
            context=["tenant", "applicant", "employee", "advisor", "draft", "student", "candidate", "client"],
        )
        self._engine.registry.add_recognizer(context_name_recognizer)

    def detect(self, text: str) -> list[DetectionResult]:
        """
        Detect PII entities in the given text.

        Parameters
        ----------
        text : str
            The input text to scan for PII.

        Returns
        -------
        list[DetectionResult]
            Detected entities sorted by start position, then by descending
            confidence score. Overlapping spans are NOT merged here — that
            is handled by the transformer module during sanitization.

        Raises
        ------
        ValueError
            If text is None.
        """
        if text is None:
            raise ValueError("Input text cannot be None")

        if not text.strip():
            return []

        # Run Presidio analysis
        raw_results: list[RecognizerResult] = self._engine.analyze(
            text=text,
            language=self.language,
            entities=self.entities,
            score_threshold=self.score_threshold,
        )

        # Convert to our DetectionResult dataclass with matched text
        detections = [
            DetectionResult(
                entity_type=r.entity_type,
                text=text[r.start : r.end],
                start=r.start,
                end=r.end,
                score=round(r.score, 4),
            )
            for r in raw_results
        ]

        # Sort by position first, then by descending score for overlaps
        detections.sort(key=lambda d: (d.start, -d.score))

        # Merge adjacent entities of the same type (e.g. "Arunima" + "Sen" -> "Arunima Sen")
        return self._merge_adjacent_entities(detections, text)

    @staticmethod
    def _merge_adjacent_entities(
        detections: list[DetectionResult], text: str
    ) -> list[DetectionResult]:
        """
        Merge adjacent entities of the same type separated only by whitespace.
        For example: [PERSON: 'Arunima'] + [PERSON: 'Sen'] -> [PERSON: 'Arunima Sen'].
        """
        if len(detections) <= 1:
            return detections

        merged: list[DetectionResult] = []
        i = 0
        while i < len(detections):
            current = detections[i]
            # Check if next entity is adjacent and of the same type
            while (
                i + 1 < len(detections)
                and detections[i + 1].entity_type == current.entity_type
                and current.entity_type in ("PERSON", "LOCATION", "ORGANIZATION")
                and detections[i + 1].start >= current.end
                and text[current.end : detections[i + 1].start].strip() == ""
                and (detections[i + 1].start - current.end) <= 2
            ):
                nxt = detections[i + 1]
                new_start = current.start
                new_end = nxt.end
                current = DetectionResult(
                    entity_type=current.entity_type,
                    text=text[new_start:new_end],
                    start=new_start,
                    end=new_end,
                    score=round(max(current.score, nxt.score), 4),
                )
                i += 1
            merged.append(current)
            i += 1
        return merged

    def detect_summary(self, text: str) -> dict:
        """
        Return a summary of detections suitable for logging (no PII values).

        Returns a dict like:
            {
                "entity_counts": {"PERSON": 2, "EMAIL_ADDRESS": 1},
                "total_entities": 3,
                "text_length": 85,
            }

        This is safe to log — it contains NO raw PII values.
        """
        detections = self.detect(text)

        counts: dict[str, int] = {}
        for d in detections:
            counts[d.entity_type] = counts.get(d.entity_type, 0) + 1

        return {
            "entity_counts": counts,
            "total_entities": len(detections),
            "text_length": len(text),
        }

    def get_supported_entities(self) -> list[str]:
        """Return the list of entity types this detector is configured to find."""
        return list(self.entities)

    def __repr__(self) -> str:
        return (
            f"PIIDetector(threshold={self.score_threshold}, "
            f"entities={len(self.entities)} types, lang={self.language!r})"
        )
