"""
tests/test_policy.py — Unit Tests for Policy Engine
======================================================

Tests:
1. Policy loading (YAML & dictionary fallback)
2. Evaluation of the 5 privacy actions:
   - ALLOW (pass through verbatim)
   - PSEUDONYMIZE (indexed placeholders, tracked in vault)
   - GENERALIZE (k-anonymity classes: cities -> regions, age -> age brackets)
   - REDACT (irreversible one-way masking, no vault storage)
   - BLOCK (hard request rejection on restricted entities or volume threshold)
3. End-to-end integration with TextTransformer

Run with: pytest tests/test_policy.py -v
"""

import pytest
from gateway.detector import DetectionResult, PIIDetector
from gateway.vault import PIIVault
from gateway.policy import PolicyEngine, PolicyAction, Generalizer
from gateway.transformer import TextTransformer


# ── Fixtures ──────────────────────────────────────────────────

@pytest.fixture
def policy_engine() -> PolicyEngine:
    return PolicyEngine("policies/default.yaml")


@pytest.fixture
def vault() -> PIIVault:
    v = PIIVault(":memory:")
    yield v
    v.close()


# ── Core Action Tests ────────────────────────────────────────

class TestPolicyActions:
    """Test policy configuration and action mapping."""

    def test_default_actions_loaded(self, policy_engine: PolicyEngine):
        """Standard entities should match configured actions."""
        assert policy_engine.get_action("PERSON") == PolicyAction.PSEUDONYMIZE
        assert policy_engine.get_action("EMAIL_ADDRESS") == PolicyAction.PSEUDONYMIZE
        assert policy_engine.get_action("IN_AADHAAR") == PolicyAction.REDACT
        assert policy_engine.get_action("CREDIT_CARD") == PolicyAction.BLOCK
        assert policy_engine.get_action("DATE_TIME") == PolicyAction.ALLOW

    def test_unspecified_fallback_to_default(self, policy_engine: PolicyEngine):
        """Unknown entities should fallback to DEFAULT action (PSEUDONYMIZE)."""
        assert policy_engine.get_action("UNKNOWN_CUSTOM_TYPE") == PolicyAction.PSEUDONYMIZE


# ── Generalization Tests ─────────────────────────────────────

class TestGeneralizer:
    """Test k-anonymity generalization heuristics."""

    def test_location_generalization(self):
        """Major Indian cities should generalize to regional metro classes."""
        assert Generalizer.generalize("LOCATION", "Bengaluru") == "<SOUTH_INDIA_METRO>"
        assert Generalizer.generalize("LOCATION", "Chennai") == "<SOUTH_INDIA_METRO>"
        assert Generalizer.generalize("LOCATION", "Delhi") == "<NORTH_INDIA_METRO>"
        assert Generalizer.generalize("LOCATION", "Mumbai") == "<WEST_INDIA_METRO>"
        assert Generalizer.generalize("LOCATION", "SmallTown") == "<GENERAL_METROPOLITAN_AREA>"

    def test_age_generalization(self):
        """Ages should generalize to 10-year age buckets."""
        assert Generalizer.generalize("AGE", "24") == "<AGE_20_TO_30>"
        assert Generalizer.generalize("AGE", "38") == "<AGE_30_TO_40>"
        assert Generalizer.generalize("AGE", "52") == "<AGE_50_TO_60>"


# ── Blocking Evaluation Tests ────────────────────────────────

class TestPolicyEvaluation:
    """Test request-level blocking and allow evaluation."""

    def test_allowed_request_passes(self, policy_engine: PolicyEngine):
        """Standard request with names and emails should not be blocked."""
        detections = [
            DetectionResult(entity_type="PERSON", text="Rahul", start=0, end=5, score=0.9),
            DetectionResult(entity_type="EMAIL_ADDRESS", text="r@t.com", start=10, end=17, score=0.9),
        ]
        decision = policy_engine.evaluate(detections)
        assert decision.is_blocked is False
        assert decision.block_reason == ""

    def test_credit_card_triggers_hard_block(self, policy_engine: PolicyEngine):
        """Credit card detection must immediately trigger a BLOCK decision."""
        detections = [
            DetectionResult(entity_type="CREDIT_CARD", text="4111-1111-1111-1111", start=0, end=19, score=0.95),
        ]
        decision = policy_engine.evaluate(detections)
        assert decision.is_blocked is True
        assert "restricted entity type 'CREDIT_CARD'" in decision.block_reason

    def test_entity_volume_limit_triggers_block(self, policy_engine: PolicyEngine):
        """Flooding request with >15 entities should be blocked."""
        many_detections = [
            DetectionResult(entity_type="PERSON", text=f"Person_{i}", start=i*5, end=(i+1)*5, score=0.8)
            for i in range(20)
        ]
        decision = policy_engine.evaluate(many_detections)
        assert decision.is_blocked is True
        assert "maximum allowed per turn" in decision.block_reason


# ── Transformer Integration Tests ────────────────────────────

class TestPolicyTransformerIntegration:
    """Test policy action execution in TextTransformer."""

    def test_aadhaar_redaction(self, vault: PIIVault):
        """Aadhaar must be masked with REDACTED and NOT stored in vault."""
        detector = PIIDetector(score_threshold=0.4)
        policy = PolicyEngine("policies/default.yaml")
        transformer = TextTransformer(detector, vault, policy=policy)

        text = "My Aadhaar is 5482 9182 3491 for ID verification."
        result = transformer.sanitize(text, session_id="s_pol")

        # Aadhaar must be masked
        assert "5482 9182 3491" not in result.sanitized_text
        assert "[REDACTED_IN_AADHAAR]" in result.sanitized_text

        # Must NOT be stored in vault (one-way redaction)
        mappings = vault.get_all_mappings("s_pol")
        assert not any("5482" in m["original_value"] for m in mappings)

        # Restoration must NOT restore redacted values
        restored = transformer.restore(result.sanitized_text, session_id="s_pol")
        assert "[REDACTED_IN_AADHAAR]" in restored
        assert "5482 9182 3491" not in restored

    def test_custom_generalize_policy(self, vault: PIIVault):
        """When LOCATION is configured to GENERALIZE, it transforms into regional class."""
        custom_config = {
            "entity_policies": {
                "LOCATION": {"action": "GENERALIZE"},
                "DEFAULT": {"action": "PSEUDONYMIZE"},
            }
        }
        policy = PolicyEngine(config_dict=custom_config)
        detector = PIIDetector(score_threshold=0.4)
        transformer = TextTransformer(detector, vault, policy=policy)

        text = "I am relocating to Bengaluru next month."
        result = transformer.sanitize(text, session_id="s_gen")

        assert "Bengaluru" not in result.sanitized_text
        assert "<SOUTH_INDIA_METRO>" in result.sanitized_text

        # Generalized values are NOT stored in vault
        mappings = vault.get_all_mappings("s_gen")
        assert not any("Bengaluru" in m["original_value"] for m in mappings)

