"""
tests/test_vault.py — Unit Tests for PII Vault
=================================================

Tests session isolation, mapping storage/retrieval, index management,
and security boundaries of the SQLite vault.

Run with: pytest tests/test_vault.py -v
"""

import pytest
from gateway.vault import PIIVault


# ── Fixtures ──────────────────────────────────────────────────

@pytest.fixture
def vault() -> PIIVault:
    """Fresh in-memory vault for each test."""
    v = PIIVault(":memory:")
    yield v
    v.close()


# ── Basic Storage & Retrieval ────────────────────────────────

class TestStorageAndRetrieval:
    """Test storing and retrieving mappings."""

    def test_store_and_get_placeholder(self, vault: PIIVault):
        """Should retrieve the placeholder for a stored original value."""
        vault.store("s1", "PERSON", "PERSON_1", "Rahul Sharma")
        result = vault.get_placeholder("s1", "Rahul Sharma")
        assert result == "PERSON_1"

    def test_store_and_get_original(self, vault: PIIVault):
        """Should retrieve the original value for a stored placeholder."""
        vault.store("s1", "EMAIL_ADDRESS", "EMAIL_1", "rahul@test.com")
        result = vault.get_original("s1", "EMAIL_1")
        assert result == "rahul@test.com"

    def test_get_placeholder_not_found(self, vault: PIIVault):
        """Should return None for unknown original values."""
        result = vault.get_placeholder("s1", "Unknown Person")
        assert result is None

    def test_get_original_not_found(self, vault: PIIVault):
        """Should return None for unknown placeholders."""
        result = vault.get_original("s1", "PERSON_99")
        assert result is None

    def test_case_insensitive_lookup(self, vault: PIIVault):
        """Lookup by original value should be case-insensitive."""
        vault.store("s1", "PERSON", "PERSON_1", "Rahul Sharma")
        assert vault.get_placeholder("s1", "rahul sharma") == "PERSON_1"
        assert vault.get_placeholder("s1", "RAHUL SHARMA") == "PERSON_1"
        assert vault.get_placeholder("s1", "Rahul Sharma") == "PERSON_1"

    def test_store_multiple_entities(self, vault: PIIVault):
        """Should store and retrieve multiple distinct entities."""
        vault.store("s1", "PERSON", "PERSON_1", "Rahul Sharma")
        vault.store("s1", "PERSON", "PERSON_2", "Priya Patel")
        vault.store("s1", "EMAIL_ADDRESS", "EMAIL_1", "rahul@test.com")

        assert vault.get_placeholder("s1", "Rahul Sharma") == "PERSON_1"
        assert vault.get_placeholder("s1", "Priya Patel") == "PERSON_2"
        assert vault.get_placeholder("s1", "rahul@test.com") == "EMAIL_1"

    def test_duplicate_store_is_ignored(self, vault: PIIVault):
        """Storing the same placeholder twice should not create duplicates."""
        vault.store("s1", "PERSON", "PERSON_1", "Rahul Sharma")
        vault.store("s1", "PERSON", "PERSON_1", "Rahul Sharma")
        mappings = vault.get_all_mappings("s1")
        person_mappings = [m for m in mappings if m["placeholder"] == "PERSON_1"]
        assert len(person_mappings) == 1


# ── Session Isolation ────────────────────────────────────────

class TestSessionIsolation:
    """Test that sessions cannot access each other's data."""

    def test_different_sessions_are_isolated(self, vault: PIIVault):
        """Session A's mappings should not be visible to Session B."""
        vault.store("session-A", "PERSON", "PERSON_1", "Rahul Sharma")
        vault.store("session-B", "PERSON", "PERSON_1", "Priya Patel")

        # Each session sees its own mapping
        assert vault.get_original("session-A", "PERSON_1") == "Rahul Sharma"
        assert vault.get_original("session-B", "PERSON_1") == "Priya Patel"

    def test_cross_session_lookup_returns_none(self, vault: PIIVault):
        """Looking up Session A's data with Session B's ID should return None."""
        vault.store("session-A", "PERSON", "PERSON_1", "Rahul Sharma")

        # Session B cannot see Session A's data
        assert vault.get_placeholder("session-B", "Rahul Sharma") is None
        assert vault.get_original("session-B", "PERSON_1") is None

    def test_delete_session_only_affects_target(self, vault: PIIVault):
        """Deleting Session A should not affect Session B."""
        vault.store("session-A", "PERSON", "PERSON_1", "Rahul Sharma")
        vault.store("session-B", "PERSON", "PERSON_1", "Priya Patel")

        vault.delete_session("session-A")

        assert vault.get_original("session-A", "PERSON_1") is None
        assert vault.get_original("session-B", "PERSON_1") == "Priya Patel"

    def test_session_stats_are_isolated(self, vault: PIIVault):
        """Session stats should only reflect that session's data."""
        vault.store("s1", "PERSON", "PERSON_1", "Rahul")
        vault.store("s1", "PERSON", "PERSON_2", "Priya")
        vault.store("s2", "EMAIL_ADDRESS", "EMAIL_1", "a@b.com")

        stats_s1 = vault.get_session_stats("s1")
        stats_s2 = vault.get_session_stats("s2")

        assert stats_s1 == {"PERSON": 2}
        assert stats_s2 == {"EMAIL_ADDRESS": 1}


# ── Index Management ─────────────────────────────────────────

class TestIndexManagement:
    """Test placeholder index auto-incrementing."""

    def test_first_index_is_one(self, vault: PIIVault):
        """First placeholder index for a new type should be 1."""
        idx = vault.get_next_index("s1", "PERSON")
        assert idx == 1

    def test_index_increments(self, vault: PIIVault):
        """Successive calls should return incrementing indices."""
        idx1 = vault.get_next_index("s1", "PERSON")
        idx2 = vault.get_next_index("s1", "PERSON")
        idx3 = vault.get_next_index("s1", "PERSON")
        assert (idx1, idx2, idx3) == (1, 2, 3)

    def test_different_types_have_independent_indices(self, vault: PIIVault):
        """PERSON and EMAIL_ADDRESS should have separate counters."""
        p1 = vault.get_next_index("s1", "PERSON")
        e1 = vault.get_next_index("s1", "EMAIL_ADDRESS")
        p2 = vault.get_next_index("s1", "PERSON")

        assert p1 == 1
        assert e1 == 1  # Independent counter
        assert p2 == 2

    def test_different_sessions_have_independent_indices(self, vault: PIIVault):
        """Each session should have its own counters."""
        vault.get_next_index("s1", "PERSON")  # s1 → 1
        vault.get_next_index("s1", "PERSON")  # s1 → 2

        idx = vault.get_next_index("s2", "PERSON")  # s2 → 1
        assert idx == 1


# ── Bulk Operations ──────────────────────────────────────────

class TestBulkOperations:
    """Test get_all_mappings and delete_session."""

    def test_get_all_mappings(self, vault: PIIVault):
        """Should return all mappings for a session."""
        vault.store("s1", "PERSON", "PERSON_1", "Rahul", turn_number=1)
        vault.store("s1", "EMAIL_ADDRESS", "EMAIL_1", "r@t.com", turn_number=2)

        mappings = vault.get_all_mappings("s1")
        assert len(mappings) == 2
        types = {m["entity_type"] for m in mappings}
        assert types == {"PERSON", "EMAIL_ADDRESS"}

    def test_get_all_mappings_empty_session(self, vault: PIIVault):
        """Should return empty list for unknown session."""
        mappings = vault.get_all_mappings("nonexistent")
        assert mappings == []

    def test_delete_session(self, vault: PIIVault):
        """Should remove all mappings for a session."""
        vault.store("s1", "PERSON", "PERSON_1", "Rahul")
        vault.store("s1", "EMAIL_ADDRESS", "EMAIL_1", "r@t.com")

        deleted = vault.delete_session("s1")
        assert deleted == 2
        assert vault.get_all_mappings("s1") == []

    def test_delete_nonexistent_session(self, vault: PIIVault):
        """Deleting a nonexistent session should return 0 and not error."""
        deleted = vault.delete_session("ghost")
        assert deleted == 0

    def test_turn_number_tracked(self, vault: PIIVault):
        """Turn numbers should be stored and retrievable."""
        vault.store("s1", "PERSON", "PERSON_1", "Rahul", turn_number=3)
        mappings = vault.get_all_mappings("s1")
        assert mappings[0]["turn_number"] == 3

