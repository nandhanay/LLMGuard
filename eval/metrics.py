"""
eval/metrics.py — Evaluation Metrics for LLM Privacy Gateway
=============================================================

Computes standard research metrics on benchmark datasets:
1. PII Detection Performance (Precision, Recall, F1 — exact & overlap matches)
2. Direct Information Leakage Rate (did raw PII leak to the LLM?)
3. Placeholder Consistency (did entities maintain the same placeholder across turns?)
4. Placeholder Restoration Accuracy (were placeholders properly restored in responses?)
5. Pipeline Latency Profiling (P50, P95, P99, Mean)
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional


# ── Metric Data Classes ───────────────────────────────────────

@dataclass
class ClassificationScores:
    """Standard precision, recall, and F1 container."""
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r) / (p + r) if (p + r) > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


@dataclass
class DetectionEvaluationReport:
    """Summary of detection precision, recall, and F1 across all turns."""
    exact_match_micro: ClassificationScores
    overlap_match_micro: ClassificationScores
    per_type_scores: dict[str, ClassificationScores]

    def to_dict(self) -> dict[str, Any]:
        return {
            "exact_match": self.exact_match_micro.to_dict(),
            "overlap_match": self.overlap_match_micro.to_dict(),
            "per_entity_type": {
                k: v.to_dict() for k, v in self.per_type_scores.items()
            },
        }


@dataclass
class LeakageReport:
    """Tracks direct PII leakage into sanitized text."""
    total_ground_truth_entities: int = 0
    leaked_entities_count: int = 0
    leaked_instances: list[dict[str, Any]] = field(default_factory=list)

    @property
    def leakage_rate(self) -> float:
        if self.total_ground_truth_entities == 0:
            return 0.0
        return self.leaked_entities_count / self.total_ground_truth_entities

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_entities": self.total_ground_truth_entities,
            "leaked_entities": self.leaked_entities_count,
            "leakage_rate": round(self.leakage_rate, 4),
            "leaked_instances": self.leaked_instances,
        }


@dataclass
class LatencyReport:
    """Processing time distribution in milliseconds."""
    samples: list[float] = field(default_factory=list)

    @property
    def mean(self) -> float:
        return statistics.mean(self.samples) if self.samples else 0.0

    @property
    def p50(self) -> float:
        return statistics.median(self.samples) if self.samples else 0.0

    @property
    def p95(self) -> float:
        if not self.samples:
            return 0.0
        sorted_s = sorted(self.samples)
        idx = int(len(sorted_s) * 0.95)
        return sorted_s[min(idx, len(sorted_s) - 1)]

    @property
    def p99(self) -> float:
        if not self.samples:
            return 0.0
        sorted_s = sorted(self.samples)
        idx = int(len(sorted_s) * 0.99)
        return sorted_s[min(idx, len(sorted_s) - 1)]

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": len(self.samples),
            "mean_ms": round(self.mean, 2),
            "p50_ms": round(self.p50, 2),
            "p95_ms": round(self.p95, 2),
            "p99_ms": round(self.p99, 2),
        }


# ── Metrics Evaluator ─────────────────────────────────────────

class MetricsEvaluator:
    """
    Evaluates detector, sanitizer, and pipeline performance against
    ground-truth annotations.
    """

    @staticmethod
    def evaluate_detections(
        ground_truth: list[dict[str, Any]],  # list of {text, start, end, entity_type}
        predictions: list[Any],             # list of DetectionResult objects
    ) -> tuple[ClassificationScores, ClassificationScores, dict[str, ClassificationScores]]:
        """
        Compare predicted entity spans against ground truth.

        Returns
        -------
        exact_scores, overlap_scores, per_type_scores
        """
        exact = ClassificationScores()
        overlap = ClassificationScores()
        per_type: dict[str, ClassificationScores] = defaultdict(ClassificationScores)

        matched_gt_exact = set()
        matched_gt_overlap = set()
        matched_pred_exact = set()
        matched_pred_overlap = set()

        # 1. Exact Match Evaluation
        for p_idx, pred in enumerate(predictions):
            for g_idx, gt in enumerate(ground_truth):
                if g_idx in matched_gt_exact:
                    continue
                # Span & Type match
                if (
                    pred.start == gt["start"]
                    and pred.end == gt["end"]
                    and pred.entity_type.upper() == gt["entity_type"].upper()
                ):
                    exact.tp += 1
                    per_type[gt["entity_type"]].tp += 1
                    matched_gt_exact.add(g_idx)
                    matched_pred_exact.add(p_idx)
                    break

        exact.fp = len(predictions) - len(matched_pred_exact)
        exact.fn = len(ground_truth) - len(matched_gt_exact)

        # 2. Overlap Match Evaluation
        for p_idx, pred in enumerate(predictions):
            for g_idx, gt in enumerate(ground_truth):
                if g_idx in matched_gt_overlap:
                    continue
                # Character overlap check: max(start1, start2) < min(end1, end2)
                has_overlap = max(pred.start, gt["start"]) < min(pred.end, gt["end"])
                if has_overlap and pred.entity_type.upper() == gt["entity_type"].upper():
                    overlap.tp += 1
                    matched_gt_overlap.add(g_idx)
                    matched_pred_overlap.add(p_idx)
                    break

        overlap.fp = len(predictions) - len(matched_pred_overlap)
        overlap.fn = len(ground_truth) - len(matched_gt_overlap)

        return exact, overlap, per_type

    @staticmethod
    def check_information_leakage(
        sanitized_text: str,
        ground_truth_entities: list[dict[str, Any]],
        conversation_id: str = "",
        turn_number: int = 1,
    ) -> LeakageReport:
        """
        Verify that no ground truth PII value exists in the sanitized text.
        """
        report = LeakageReport(total_ground_truth_entities=len(ground_truth_entities))

        for gt in ground_truth_entities:
            val = gt["text"].strip()
            # If the raw value is 3+ characters and appears verbatim in sanitized text
            if len(val) >= 3 and val.lower() in sanitized_text.lower():
                report.leaked_entities_count += 1
                report.leaked_instances.append({
                    "conversation_id": conversation_id,
                    "turn": turn_number,
                    "entity_type": gt["entity_type"],
                    "leaked_value": val,
                })

        return report
