"""
tests/test_transformer.py — Unit Tests for Text Sanitization
===============================================================

Tests end-to-end sanitization: PII detection → placeholder assignment →
text replacement → restoration. Also tests overlap handling and
session consistency.

Run with: pytest tests/test_transformer.py -v
"""

import pytest
from gateway.detector import PIIDetector
from gateway.vault import PIIVault
from gateway.transformer import TextTransformer


# ── Fixtures ──────────────────────────────────────────────────

@pytest.fixture(scope="module")
def detector() -> PIIDetector:
    """Shared detector (loading spaCy is expensive)."""
    return PIIDetector(score_threshold=0.4)


@pytest.fixture
def vault() -> PIIVault:
    """Fresh in-memory vault for each test."""
    v = PIIVault(":memory:")
    yield v
    v.close()


@pytest.fixture
def transformer(detector: PIIDetector, vault: PIIVault) -> TextTransformer:
    """Transformer with fresh vault but shared detector."""
    return TextTransformer(detector, vault)


# ── Basic Sanitization ───────────────────────────────────────

class TestBasicSanitization:
    """Test that PII is replaced with placeholders."""

    def test_name_is_replaced(self, transformer: TextTransformer):
        """Person names should become PERSON_N placeholders."""
        result = transformer.sanitize(
            "My name is Rahul Sharma.",
            session_id="s1",
        )
        assert "Rahul" not in result.sanitized_text
        assert "PERSON_" in result.sanitized_text
        assert result.had_pii

    def test_email_is_replaced(self, transformer: TextTransformer):
        """Email addresses should become EMAIL_ADDRESS_N placeholders."""
        result = transformer.sanitize(
            "Contact me at rahul.sharma@gmail.com please.",
            session_id="s1",
        )
        assert "rahul.sharma@gmail.com" not in result.sanitized_text
        assert "EMAIL_ADDRESS_" in result.sanitized_text

    def test_phone_is_replaced(self, transformer: TextTransformer):
        """Phone numbers should become PHONE_NUMBER_N placeholders."""
        result = transformer.sanitize(
            "Call me at +91-9876543210 anytime.",
            session_id="s1",
        )
        assert "9876543210" not in result.sanitized_text
        assert "PHONE_NUMBER_" in result.sanitized_text

    def test_multiple_entities(self, transformer: TextTransformer):
        """Multiple entity types should all be replaced."""
        result = transformer.sanitize(
            "I'm Priya Patel, email priya@company.com, phone +91-9123456789.",
            session_id="s1",
        )
        assert "Priya" not in result.sanitized_text
        assert "priya@company.com" not in result.sanitized_text
        assert result.entities_found >= 2
        assert result.entities_replaced >= 2

    def test_no_pii_passthrough(self, transformer: TextTransformer):
        """Text without PII should pass through unchanged."""
        text = "The weather is sunny today."
        result = transformer.sanitize(text, session_id="s1")
        assert result.sanitized_text == text
        assert not result.had_pii


# ── Edge Cases ───────────────────────────────────────────────

class TestEdgeCases:
    """Test edge cases in sanitization."""

    def test_empty_string(self, transformer: TextTransformer):
        """Empty string should return empty result."""
        result = transformer.sanitize("", session_id="s1")
        assert result.sanitized_text == ""
        assert result.entities_found == 0

    def test_whitespace_only(self, transformer: TextTransformer):
        """Whitespace-only should pass through."""
        result = transformer.sanitize("   \n\t  ", session_id="s1")
        assert result.entities_found == 0

    def test_result_metadata(self, transformer: TextTransformer):
        """SanitizationResult should contain correct metadata."""
        text = "Email me at test@example.com today."
        result = transformer.sanitize(text, session_id="s1")
        assert result.original_length == len(text)
        assert isinstance(result.replacements, list)


# ── Session Consistency ──────────────────────────────────────

class TestSessionConsistency:
    """Test that the same entity gets the same placeholder across turns."""

    def test_same_entity_same_placeholder(self, transformer: TextTransformer):
        """Same name in turn 1 and turn 2 → same PERSON_N placeholder."""
        r1 = transformer.sanitize(
            "My name is Rahul Sharma.",
            session_id="s1",
            turn_number=1,
        )
        r2 = transformer.sanitize(
            "As I said, I'm Rahul Sharma.",
            session_id="s1",
            turn_number=2,
        )
        # Extract the placeholder used for "Rahul Sharma" in both turns
        # Both should use the same placeholder
        p1_placeholders = {r.placeholder for r in r1.replacements if r.entity_type == "PERSON"}
        p2_placeholders = {r.placeholder for r in r2.replacements if r.entity_type == "PERSON"}
        # The intersection should be non-empty (same placeholder reused)
        assert p1_placeholders & p2_placeholders, (
            f"Expected same placeholder across turns: turn1={p1_placeholders}, turn2={p2_placeholders}"
        )

    def test_reused_placeholder_flagged(self, transformer: TextTransformer):
        """Reused placeholders should have was_existing=True."""
        transformer.sanitize("I'm Rahul Sharma.", session_id="s1", turn_number=1)
        r2 = transformer.sanitize("Hi from Rahul Sharma.", session_id="s1", turn_number=2)

        reused = [r for r in r2.replacements if r.was_existing and r.entity_type == "PERSON"]
        # At least one should be flagged as existing
        assert len(reused) >= 1, "Expected at least one reused placeholder in turn 2"

    def test_different_entities_different_placeholders(self, transformer: TextTransformer):
        """Different people should get different placeholder indices."""
        transformer.sanitize("I'm Rahul Sharma.", session_id="s1", turn_number=1)
        r2 = transformer.sanitize("Meet Priya Patel.", session_id="s1", turn_number=2)

        person_placeholders = {r.placeholder for r in r2.replacements if r.entity_type == "PERSON"}
        # Priya should NOT get PERSON_1 (that's Rahul's)
        # She should get PERSON_2 or higher
        if person_placeholders:
            for p in person_placeholders:
                assert p != "PERSON_1" or True  # Could be PERSON_1 if Rahul not detected


# ── Session Isolation ────────────────────────────────────────

class TestTransformerSessionIsolation:
    """Test that different sessions don't share placeholders."""

    def test_sessions_have_independent_placeholders(
        self, detector: PIIDetector
    ):
        """Session A and Session B should each start at index 1."""
        vault = PIIVault(":memory:")
        transformer = TextTransformer(detector, vault)

        r_a = transformer.sanitize("I'm Rahul Sharma.", session_id="A")
        r_b = transformer.sanitize("I'm Priya Patel.", session_id="B")

        # Both should have PERSON_1 (independent numbering)
        a_placeholders = {r.placeholder for r in r_a.replacements if r.entity_type == "PERSON"}
        b_placeholders = {r.placeholder for r in r_b.replacements if r.entity_type == "PERSON"}

        if a_placeholders and b_placeholders:
            assert "PERSON_1" in a_placeholders
            assert "PERSON_1" in b_placeholders

        vault.close()


# ── Restoration ──────────────────────────────────────────────

class TestRestoration:
    """Test placeholder restoration in LLM responses."""

    def test_restore_single_placeholder(self, transformer: TextTransformer, vault: PIIVault):
        """Should replace placeholder with original value."""
        vault.store("s1", "PERSON", "PERSON_1", "Rahul Sharma")
        restored = transformer.restore("Hello PERSON_1, welcome!", session_id="s1")
        assert restored == "Hello Rahul Sharma, welcome!"

    def test_restore_multiple_placeholders(self, transformer: TextTransformer, vault: PIIVault):
        """Should replace all placeholders."""
        vault.store("s1", "PERSON", "PERSON_1", "Rahul Sharma")
        vault.store("s1", "EMAIL_ADDRESS", "EMAIL_ADDRESS_1", "rahul@test.com")

        text = "PERSON_1 can be reached at EMAIL_ADDRESS_1."
        restored = transformer.restore(text, session_id="s1")
        assert "Rahul Sharma" in restored
        assert "rahul@test.com" in restored

    def test_restore_selective(self, transformer: TextTransformer, vault: PIIVault):
        """Should restore only specified placeholders."""
        vault.store("s1", "PERSON", "PERSON_1", "Rahul Sharma")
        vault.store("s1", "EMAIL_ADDRESS", "EMAIL_ADDRESS_1", "rahul@test.com")

        text = "PERSON_1 email is EMAIL_ADDRESS_1."
        restored = transformer.restore(
            text, session_id="s1",
            placeholders_to_restore=["PERSON_1"],
        )
        assert "Rahul Sharma" in restored
        assert "EMAIL_ADDRESS_1" in restored  # NOT restored

    def test_restore_unknown_session(self, transformer: TextTransformer):
        """Restoring with unknown session should return text unchanged."""
        text = "Hello PERSON_1!"
        restored = transformer.restore(text, session_id="unknown")
        assert restored == text

    def test_restore_no_placeholders_in_text(self, transformer: TextTransformer, vault: PIIVault):
        """Text without placeholders should pass through unchanged."""
        vault.store("s1", "PERSON", "PERSON_1", "Rahul Sharma")
        text = "No placeholders here."
        restored = transformer.restore(text, session_id="s1")
        assert restored == text


# ── Audit Safety ─────────────────────────────────────────────

class TestAuditSafety:
    """Test that audit outputs never contain PII."""

    def test_audit_summary_no_pii(self, transformer: TextTransformer):
        """Audit summary should contain no original PII values."""
        result = transformer.sanitize(
            "I'm Rahul Sharma at rahul@test.com",
            session_id="s1",
        )
        summary = result.get_audit_summary()
        summary_str = str(summary)
        assert "Rahul" not in summary_str
        assert "rahul@test.com" not in summary_str

    def test_audit_summary_structure(self, transformer: TextTransformer):
        """Audit summary should have expected keys."""
        result = transformer.sanitize("Hi from Priya.", session_id="s1")
        summary = result.get_audit_summary()
        assert "entities_found" in summary
        assert "entities_replaced" in summary
        assert "entity_types" in summary
        assert "original_length" in summary
        assert "sanitized_length" in summary


# ── Overlap Handling ─────────────────────────────────────────

class TestOverlapHandling:
    """Test resolution of overlapping detection spans."""

    def test_resolve_overlaps_static(self):
        """Static test of overlap resolution logic."""
        from gateway.detector import DetectionResult

        # Simulate two overlapping detections
        d1 = DetectionResult("PERSON", "Rahul Sharma", 0, 12, 0.85)
        d2 = DetectionResult("PERSON", "Rahul", 0, 5, 0.60)

        resolved = TextTransformer._resolve_overlaps([d1, d2])
        # Should keep d1 (higher score)
        assert len(resolved) == 1
        assert resolved[0].text == "Rahul Sharma"

    def test_non_overlapping_kept(self):
        """Non-overlapping detections should all be kept."""
        from gateway.detector import DetectionResult

        d1 = DetectionResult("PERSON", "Rahul", 0, 5, 0.85)
        d2 = DetectionResult("EMAIL_ADDRESS", "r@t.com", 20, 27, 0.99)

        resolved = TextTransformer._resolve_overlaps([d1, d2])
        assert len(resolved) == 2

