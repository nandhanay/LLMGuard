"""
tests/test_detector.py — Unit Tests for PII Detection
=======================================================

Tests the PIIDetector class against known inputs with expected entity types.
Run with: pytest tests/test_detector.py -v
"""

import pytest
from gateway.detector import PIIDetector, DetectionResult


# ── Fixtures ──────────────────────────────────────────────────

@pytest.fixture(scope="module")
def detector() -> PIIDetector:
    """Shared detector instance (loading spaCy model is expensive)."""
    return PIIDetector(score_threshold=0.4)  # Lower threshold for test coverage


@pytest.fixture(scope="module")
def strict_detector() -> PIIDetector:
    """Detector with higher confidence threshold."""
    return PIIDetector(score_threshold=0.85)


# ── Basic Detection Tests ────────────────────────────────────

class TestBasicDetection:
    """Test detection of individual PII entity types."""

    def test_detect_person_name(self, detector: PIIDetector):
        """Should detect person names."""
        results = detector.detect("My name is Rahul Sharma and I live in Delhi.")
        types = {r.entity_type for r in results}
        assert "PERSON" in types, f"Expected PERSON in {types}"
        # Verify the detected name text
        person_results = [r for r in results if r.entity_type == "PERSON"]
        assert any("Rahul" in r.text for r in person_results)

    def test_detect_email(self, detector: PIIDetector):
        """Should detect email addresses."""
        results = detector.detect("Contact me at rahul.sharma@example.com for details.")
        types = {r.entity_type for r in results}
        assert "EMAIL_ADDRESS" in types, f"Expected EMAIL_ADDRESS in {types}"
        email_results = [r for r in results if r.entity_type == "EMAIL_ADDRESS"]
        assert any("rahul.sharma@example.com" in r.text for r in email_results)

    def test_detect_phone_number(self, detector: PIIDetector):
        """Should detect phone numbers."""
        results = detector.detect("Call me at +91-9876543210 anytime.")
        types = {r.entity_type for r in results}
        assert "PHONE_NUMBER" in types, f"Expected PHONE_NUMBER in {types}"

    def test_detect_multiple_entities(self, detector: PIIDetector):
        """Should detect multiple entity types in one sentence."""
        text = (
            "My name is Priya Patel, my email is priya@company.com, "
            "and my phone is +91-9123456789."
        )
        results = detector.detect(text)
        types = {r.entity_type for r in results}
        assert "PERSON" in types
        assert "EMAIL_ADDRESS" in types
        assert "PHONE_NUMBER" in types

    def test_detect_credit_card(self, detector: PIIDetector):
        """Should detect credit card numbers."""
        results = detector.detect("My card number is 4111-1111-1111-1111.")
        types = {r.entity_type for r in results}
        assert "CREDIT_CARD" in types, f"Expected CREDIT_CARD in {types}"

    def test_detect_ip_address(self, detector: PIIDetector):
        """Should detect IP addresses."""
        results = detector.detect("The server is at 192.168.1.100 on port 8080.")
        types = {r.entity_type for r in results}
        assert "IP_ADDRESS" in types, f"Expected IP_ADDRESS in {types}"

    def test_detect_url(self, detector: PIIDetector):
        """Should detect URLs."""
        results = detector.detect("Visit https://www.example.com/profile for details.")
        types = {r.entity_type for r in results}
        assert "URL" in types, f"Expected URL in {types}"


# ── Edge Cases ───────────────────────────────────────────────

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_string(self, detector: PIIDetector):
        """Empty string should return no results."""
        results = detector.detect("")
        assert results == []

    def test_whitespace_only(self, detector: PIIDetector):
        """Whitespace-only string should return no results."""
        results = detector.detect("   \n\t  ")
        assert results == []

    def test_no_pii(self, detector: PIIDetector):
        """Text without PII should return no results (or very few)."""
        results = detector.detect("The weather is sunny today.")
        # Some generic words might trigger low-confidence matches,
        # but with default threshold they should be filtered out
        person_results = [r for r in results if r.entity_type == "PERSON"]
        # "sunny" should not be detected as a person
        assert not any("sunny" in r.text.lower() for r in person_results)

    def test_none_input_raises(self, detector: PIIDetector):
        """None input should raise ValueError."""
        with pytest.raises(ValueError, match="cannot be None"):
            detector.detect(None)

    def test_single_character(self, detector: PIIDetector):
        """Single character should not crash."""
        results = detector.detect("A")
        assert isinstance(results, list)


# ── Result Structure Tests ───────────────────────────────────

class TestResultStructure:
    """Test that DetectionResult objects have correct structure."""

    def test_result_fields(self, detector: PIIDetector):
        """Each result should have all required fields."""
        results = detector.detect("Email: test@example.com")
        assert len(results) > 0
        r = results[0]
        assert isinstance(r.entity_type, str)
        assert isinstance(r.text, str)
        assert isinstance(r.start, int)
        assert isinstance(r.end, int)
        assert isinstance(r.score, float)

    def test_result_positions_match_text(self, detector: PIIDetector):
        """start/end positions should extract the correct text."""
        text = "Contact priya@example.com for info."
        results = detector.detect(text)
        for r in results:
            assert text[r.start : r.end] == r.text, (
                f"Position mismatch: text[{r.start}:{r.end}] = "
                f"{text[r.start:r.end]!r} but result.text = {r.text!r}"
            )

    def test_results_sorted_by_position(self, detector: PIIDetector):
        """Results should be sorted by start position."""
        text = "Amit (amit@test.com) called Priya at +91-9000000000."
        results = detector.detect(text)
        positions = [r.start for r in results]
        assert positions == sorted(positions), "Results should be sorted by start position"

    def test_score_in_range(self, detector: PIIDetector):
        """Confidence scores should be between 0 and 1."""
        results = detector.detect("My name is Arjun Kumar.")
        for r in results:
            assert 0.0 <= r.score <= 1.0, f"Score {r.score} out of range"

    def test_result_is_frozen(self, detector: PIIDetector):
        """DetectionResult should be immutable (frozen dataclass)."""
        results = detector.detect("Email: test@example.com")
        if results:
            with pytest.raises(AttributeError):
                results[0].text = "tampered"


# ── Threshold Tests ──────────────────────────────────────────

class TestThresholds:
    """Test that score thresholds filter results correctly."""

    def test_strict_threshold_filters_more(
        self, detector: PIIDetector, strict_detector: PIIDetector
    ):
        """Higher threshold should produce fewer or equal results."""
        text = "Rahul at rahul@test.com called from 9876543210."
        normal = detector.detect(text)
        strict = strict_detector.detect(text)
        assert len(strict) <= len(normal), (
            f"Strict ({len(strict)}) should not exceed normal ({len(normal)})"
        )

    def test_zero_threshold(self):
        """Threshold 0.0 should include all detections."""
        d = PIIDetector(score_threshold=0.0)
        results = d.detect("Rahul Sharma lives in Mumbai.")
        # With zero threshold, should find more or equal results
        assert len(results) >= 1


# ── Summary Tests ────────────────────────────────────────────

class TestDetectSummary:
    """Test the detect_summary method (audit-safe output)."""

    def test_summary_structure(self, detector: PIIDetector):
        """Summary should have expected keys."""
        summary = detector.detect_summary("Rahul at rahul@test.com")
        assert "entity_counts" in summary
        assert "total_entities" in summary
        assert "text_length" in summary
        assert isinstance(summary["entity_counts"], dict)
        assert isinstance(summary["total_entities"], int)
        assert isinstance(summary["text_length"], int)

    def test_summary_no_pii_values(self, detector: PIIDetector):
        """Summary should NOT contain any raw PII text."""
        text = "Priya Patel at priya@company.com"
        summary = detector.detect_summary(text)
        summary_str = str(summary)
        assert "Priya" not in summary_str
        assert "priya@company.com" not in summary_str

    def test_summary_counts(self, detector: PIIDetector):
        """Summary counts should match detection count."""
        text = "Rahul at rahul@test.com"
        summary = detector.detect_summary(text)
        detections = detector.detect(text)
        assert summary["total_entities"] == len(detections)


# ── Indian Context Tests ─────────────────────────────────────

class TestIndianContext:
    """Test detection with Indian names, numbers, and identifiers."""

    def test_indian_names(self, detector: PIIDetector):
        """Should detect common Indian names."""
        results = detector.detect(
            "Ananya Krishnamurthy and Vikram Deshmukh attended the meeting."
        )
        person_results = [r for r in results if r.entity_type == "PERSON"]
        assert len(person_results) >= 1, "Should detect at least one Indian name"

    def test_indian_phone_format(self, detector: PIIDetector):
        """Should detect Indian phone number formats."""
        results = detector.detect("My number is +91 98765 43210.")
        types = {r.entity_type for r in results}
        assert "PHONE_NUMBER" in types, f"Expected PHONE_NUMBER in {types}"

    def test_mixed_indian_context(self, detector: PIIDetector):
        """Should detect PII in a realistic Indian context sentence."""
        text = (
            "Hi, I am Deepika Menon from Bangalore. "
            "You can reach me at deepika.menon@gmail.com or +91-8899776655."
        )
        results = detector.detect(text)
        types = {r.entity_type for r in results}
        assert "PERSON" in types or "EMAIL_ADDRESS" in types, (
            f"Expected PERSON or EMAIL_ADDRESS in {types}"
        )
