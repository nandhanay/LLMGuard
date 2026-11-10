"""
gateway/policy.py — Privacy Policy Engine
============================================

Loads and enforces configurable privacy policies mapped to 5 core actions:
  1. ALLOW         — Permit entity to pass through verbatim (e.g. DATE_TIME)
  2. PSEUDONYMIZE  — Replace with indexed, restorable placeholder (e.g. PERSON_1)
  3. GENERALIZE    — Transform exact data into broader categories (e.g. Bengaluru -> <SOUTH_INDIA_METRO>)
  4. REDACT        — Irreversibly mask ultra-sensitive data (e.g. [REDACTED_AADHAAR])
  5. BLOCK         — Halt request immediately (e.g. payment credentials, prompt abuse)

Usage:
    from gateway.policy import PolicyEngine, PolicyAction

    policy = PolicyEngine("policies/default.yaml")
    decision = policy.evaluate(detections)
    if decision.is_blocked:
        raise HTTPException(status_code=403, detail=decision.block_reason)
"""

from __future__ import annotations

import re
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import yaml

from gateway.detector import DetectionResult


# ── Policy Action Enum ────────────────────────────────────────

class PolicyAction(str, Enum):
    """The 5 supported privacy actions."""
    ALLOW = "ALLOW"
    PSEUDONYMIZE = "PSEUDONYMIZE"
    GENERALIZE = "GENERALIZE"
    REDACT = "REDACT"
    BLOCK = "BLOCK"


# ── Policy Evaluation Decision ────────────────────────────────

class PolicyDecision:
    """Outcome of evaluating policy against detected entities."""

    def __init__(
        self,
        is_blocked: bool = False,
        block_reason: str = "",
        actions_by_entity: Optional[dict[str, PolicyAction]] = None,
    ):
        self.is_blocked = is_blocked
        self.block_reason = block_reason
        self.actions_by_entity = actions_by_entity or {}

    def __repr__(self) -> str:
        return (
            f"PolicyDecision(blocked={self.is_blocked}, "
            f"reason={self.block_reason!r}, "
            f"actions={len(self.actions_by_entity)})"
        )


# ── Generalizer Heuristics ────────────────────────────────────

# Regional Indian City Buckets for k-Anonymity Generalization
CITY_REGIONS: dict[str, str] = {
    "bengaluru": "<SOUTH_INDIA_METRO>",
    "bangalore": "<SOUTH_INDIA_METRO>",
    "chennai": "<SOUTH_INDIA_METRO>",
    "hyderabad": "<SOUTH_INDIA_METRO>",
    "kochi": "<SOUTH_INDIA_METRO>",
    "delhi": "<NORTH_INDIA_METRO>",
    "new delhi": "<NORTH_INDIA_METRO>",
    "noida": "<NORTH_INDIA_METRO>",
    "gurugram": "<NORTH_INDIA_METRO>",
    "gurgaon": "<NORTH_INDIA_METRO>",
    "mumbai": "<WEST_INDIA_METRO>",
    "pune": "<WEST_INDIA_METRO>",
    "ahmedabad": "<WEST_INDIA_METRO>",
    "kolkata": "<EAST_INDIA_METRO>",
}


class Generalizer:
    """Transforms specific attribute values into broader k-anonymity classes."""

    @staticmethod
    def generalize(entity_type: str, text: str) -> str:
        clean = text.strip()

        # 1. Location Generalization (City -> Region)
        if entity_type == "LOCATION":
            norm = clean.lower()
            if norm in CITY_REGIONS:
                return CITY_REGIONS[norm]
            return "<GENERAL_METROPOLITAN_AREA>"

        # 2. Age / Numeric Generalization (e.g. "34" -> "<AGE_30_TO_40>")
        if entity_type in ("AGE", "NUMBER") and clean.isdigit():
            val = int(clean)
            if 0 <= val <= 120:
                lower = (val // 10) * 10
                upper = lower + 10
                return f"<AGE_{lower}_TO_{upper}>"

        # 3. Organization Generalization
        if entity_type == "ORGANIZATION":
            return "<ENTERPRISE_ORGANIZATION>"

        # 4. Fallback generic class
        return f"<GENERALIZED_{entity_type}>"


# ── Policy Engine ─────────────────────────────────────────────

class PolicyEngine:
    """
    Parses and enforces privacy policy rules across detected entities.
    """

    DEFAULT_POLICY: dict[str, Any] = {
        "version": "1.0",
        "detection_threshold": 0.7,
        "max_entities_per_turn": 12,
        "entity_policies": {
            "PERSON": {"action": "PSEUDONYMIZE"},
            "EMAIL_ADDRESS": {"action": "PSEUDONYMIZE"},
            "PHONE_NUMBER": {"action": "PSEUDONYMIZE"},
            "LOCATION": {"action": "PSEUDONYMIZE"},
            "IN_PAN": {"action": "PSEUDONYMIZE"},
            "IN_AADHAAR": {"action": "REDACT"},
            "CREDIT_CARD": {"action": "BLOCK"},
            "US_SSN": {"action": "BLOCK"},
            "DATE_TIME": {"action": "ALLOW"},
            "DEFAULT": {"action": "PSEUDONYMIZE"},
        },
    }

    def __init__(
        self,
        config_path: Optional[str | Path] = None,
        config_dict: Optional[dict[str, Any]] = None,
    ):
        if config_dict:
            self._config = config_dict
        elif config_path and Path(config_path).exists():
            with open(config_path, "r", encoding="utf-8") as f:
                self._config = yaml.safe_load(f) or self.DEFAULT_POLICY
        else:
            self._config = self.DEFAULT_POLICY

        self._entity_policies = self._config.get("entity_policies", {})
        self._max_entities = self._config.get("max_entities_per_turn", 15)

    def get_action(self, entity_type: str) -> PolicyAction:
        """Look up the configured action for an entity type."""
        entry = self._entity_policies.get(entity_type)
        if not entry:
            entry = self._entity_policies.get("DEFAULT", {"action": "PSEUDONYMIZE"})

        action_str = entry.get("action", "PSEUDONYMIZE").upper()
        try:
            return PolicyAction(action_str)
        except ValueError:
            return PolicyAction.PSEUDONYMIZE

    def evaluate(self, detections: list[DetectionResult]) -> PolicyDecision:
        """
        Evaluate full request against policy rules.
        Checks for BLOCK actions and entity count limits.
        """
        # Rule 1: Volume Flood Check
        if len(detections) > self._max_entities:
            return PolicyDecision(
                is_blocked=True,
                block_reason=(
                    f"Privacy policy violation: request contains {len(detections)} sensitive entities "
                    f"(maximum allowed per turn is {self._max_entities})."
                ),
            )

        actions_map: dict[str, PolicyAction] = {}

        # Rule 2: Per-Entity Action Resolution & Hard Block Trigger
        for det in detections:
            action = self.get_action(det.entity_type)
            actions_map[det.entity_type] = action

            if action == PolicyAction.BLOCK:
                return PolicyDecision(
                    is_blocked=True,
                    block_reason=(
                        f"Request blocked by privacy policy: restricted entity type '{det.entity_type}' "
                        f"detected with high confidence."
                    ),
                    actions_by_entity=actions_map,
                )

        return PolicyDecision(
            is_blocked=False,
            block_reason="",
            actions_by_entity=actions_map,
        )

    def generalize_text(self, entity_type: str, raw_text: str) -> str:
        """Convenience method to generalize a specific entity value."""
        return Generalizer.generalize(entity_type, raw_text)
