"""
tests/test_resolver.py — Unit Tests for Alias Resolution
===========================================================

Tests:
1. Alias extraction (first name, surname, honorific combinations)
2. Alias registration in vault
3. Resolution of aliases in subsequent conversation turns
4. Cross-turn consistency with identical canonical placeholder

Run with: pytest tests/test_resolver.py -v
"""

import pytest
from gateway.detector import PIIDetector, DetectionResult
from gateway.vault import PIIVault
from gateway.resolver import AliasResolver
from gateway.transformer import TextTransformer


@pytest.fixture
def vault():
    v = PIIVault(":memory:")
    yield v
    v.close()


@pytest.fixture
def resolver(vault):
    return AliasResolver(vault)


class TestAliasResolver:
    """Test suite for AliasResolver."""

    def test_extract_aliases_standard(self, resolver: AliasResolver):
        """Should derive first name and last name aliases."""
        aliases = resolver.extract_aliases("PERSON", "Arunima Sen")
        assert "Arunima" in aliases
        assert "Sen" in aliases

    def test_extract_aliases_with_honorific(self, resolver: AliasResolver):
        """Should derive clean aliases from honorific names."""
        aliases = resolver.extract_aliases("PERSON", "Dr. Vikram Deshmukh")
        assert "Vikram" in aliases
        assert "Deshmukh" in aliases
        assert "Dr. Deshmukh" in aliases

    def test_register_and_lookup_aliases(self, resolver: AliasResolver, vault: PIIVault):
        """Should store and look up aliases mapped to the same placeholder."""
        resolver.register_aliases("s1", "PERSON", "Rahul Sharma", "PERSON_1")

        assert vault.get_alias_placeholder("s1", "Rahul") == "PERSON_1"
        assert vault.get_alias_placeholder("s1", "Sharma") == "PERSON_1"
        assert vault.get_alias_placeholder("s1", "Unknown") is None

    def test_resolve_session_aliases_in_text(self, resolver: AliasResolver, vault: PIIVault):
        """Should detect known aliases in text even without standard NER."""
        resolver.register_aliases("s1", "PERSON", "Deepika Menon", "PERSON_1")

        text = "Please send the file to Deepika tomorrow."
        # Simulate empty detections from standard NER (e.g. NER missed single first name)
        resolved = resolver.resolve_session_aliases(
            text=text,
            session_id="s1",
            existing_detections=[],
        )

        assert len(resolved) == 1
        assert resolved[0].entity_type == "PERSON"
        assert resolved[0].text == "Deepika"
        assert resolved[0].start == 24
        assert resolved[0].end == 31

    def test_end_to_end_transformer_alias_consistency(self, vault: PIIVault):
        """Full transformer pipeline must map alias to the same placeholder."""
        detector = PIIDetector(score_threshold=0.5)
        transformer = TextTransformer(detector, vault)

        # Turn 1: Introduce full name
        t1 = transformer.sanitize(
            "My name is Arunima Sen.",
            session_id="s_e2e",
            turn_number=1,
        )
        assert len(t1.replacements) >= 1
        full_name_ph = t1.replacements[0].placeholder
        assert "Arunima" not in t1.sanitized_text
        assert full_name_ph in t1.sanitized_text

        # Turn 2: Mention only first name
        t2 = transformer.sanitize(
            "Draft a response on behalf of Arunima.",
            session_id="s_e2e",
            turn_number=2,
        )
        assert "Arunima" not in t2.sanitized_text
        # Must reuse the same placeholder from turn 1
        assert full_name_ph in t2.sanitized_text
        assert any(r.placeholder == full_name_ph and r.was_existing for r in t2.replacements)

