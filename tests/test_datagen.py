"""
tests/test_datagen.py — Unit Tests for Synthetic Dataset Generator
====================================================================

Tests:
1. Dataset generation with Faker (en_IN)
2. Character offset integrity (prompt[start:end] == text)
3. Entity categorization (Direct vs Quasi identifiers)
4. Schema compliance (conversation_id, scenario, provenance, turns)

Run with: pytest tests/test_datagen.py -v
"""

import pytest
from eval.datagen import SyntheticDatasetGenerator


@pytest.fixture(scope="module")
def dataset():
    gen = SyntheticDatasetGenerator(seed=123)
    return gen.generate_dataset(count=4)


class TestSyntheticDatasetGenerator:
    """Test suite for Faker-based synthetic data generator."""

    def test_generated_count(self, dataset):
        """Should generate the requested count of conversations."""
        assert len(dataset) == 4

    def test_schema_keys(self, dataset):
        """Each conversation must adhere to the common dataset JSON schema."""
        required_keys = {
            "conversation_id",
            "scenario",
            "dataset_source",
            "license",
            "provenance",
            "ground_truth_profile",
            "entities",
            "turns",
        }
        for conv in dataset:
            assert required_keys.issubset(conv.keys())
            assert len(conv["turns"]) == 5
            assert len(conv["entities"]) >= 3

    def test_character_offsets_exact_match(self, dataset):
        """All start:end annotation offsets must precisely slice the prompt text."""
        for conv in dataset:
            for turn in conv["turns"]:
                prompt = turn["user_prompt"]
                for ann in turn["annotations"]:
                    sliced = prompt[ann["start"] : ann["end"]]
                    assert sliced == ann["text"], (
                        f"Offset mismatch in {conv['conversation_id']} turn {turn['turn_number']}: "
                        f"expected {ann['text']!r}, got {sliced!r} at span ({ann['start']}, {ann['end']})"
                    )

    def test_identifier_categories_present(self, dataset):
        """Must correctly assign DIRECT and QUASI identifier categories."""
        direct_found = False
        quasi_found = False

        for conv in dataset:
            for entity in conv["entities"]:
                cat = entity["identifier_category"]
                if cat == "DIRECT_IDENTIFIER":
                    direct_found = True
                elif cat == "QUASI_IDENTIFIER":
                    quasi_found = True

        assert direct_found is True, "Expected to find DIRECT_IDENTIFIER entities"
        assert quasi_found is True, "Expected to find QUASI_IDENTIFIER entities"

    def test_reproducibility(self):
        """Same seed must produce identical dataset outputs."""
        gen1 = SyntheticDatasetGenerator(seed=42)
        gen2 = SyntheticDatasetGenerator(seed=42)

        d1 = gen1.generate_dataset(count=2)
        d2 = gen2.generate_dataset(count=2)

        # Ignore timestamp in provenance for equality check
        for d in (d1, d2):
            for c in d:
                c["provenance"].pop("generated_at", None)

        assert d1 == d2

