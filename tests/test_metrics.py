"""
tests/test_metrics.py — Unit Tests for Evaluation Metrics
===========================================================

Tests:
1. Exact match and overlap match classification calculation
2. Direct information leakage detection
3. Latency profiling statistics

Run with: pytest tests/test_metrics.py -v
"""

import pytest
from eval.metrics import ClassificationScores, LatencyReport, MetricsEvaluator
from gateway.detector import DetectionResult


class TestMetrics:
    """Test suite for research metrics calculation."""

    def test_classification_scores_perfect(self):
        """100% precision, recall, and F1 when no FP or FN."""
        scores = ClassificationScores(tp=10, fp=0, fn=0)
        assert scores.precision == 1.0
        assert scores.recall == 1.0
        assert scores.f1 == 1.0

    def test_classification_scores_mixed(self):
        """Mixed TP, FP, FN calculation."""
        scores = ClassificationScores(tp=8, fp=2, fn=2)
        assert scores.precision == 0.8
        assert scores.recall == 0.8
        assert round(scores.f1, 2) == 0.8

    def test_classification_scores_zero(self):
        """Avoid ZeroDivisionError when counts are 0."""
        scores = ClassificationScores(tp=0, fp=0, fn=0)
        assert scores.precision == 0.0
        assert scores.recall == 0.0
        assert scores.f1 == 0.0

    def test_exact_and_overlap_matching(self):
        """MetricsEvaluator should accurately distinguish exact vs overlap matches."""
        ground_truth = [
            {"entity_type": "PERSON", "text": "Rahul Sharma", "start": 0, "end": 12},
            {"entity_type": "EMAIL_ADDRESS", "text": "rahul@test.com", "start": 20, "end": 34},
        ]
        predictions = [
            # Exact match for PERSON
            DetectionResult(entity_type="PERSON", text="Rahul Sharma", start=0, end=12, score=0.9),
            # Overlap (partial) match for EMAIL_ADDRESS (e.g. detected without domain)
            DetectionResult(entity_type="EMAIL_ADDRESS", text="rahul", start=20, end=25, score=0.8),
            # False positive
            DetectionResult(entity_type="LOCATION", text="Mars", start=40, end=44, score=0.6),
        ]

        exact, overlap, per_type = MetricsEvaluator.evaluate_detections(ground_truth, predictions)

        # Exact: 1 TP (PERSON), 2 FP, 1 FN (EMAIL)
        assert exact.tp == 1
        assert exact.fp == 2
        assert exact.fn == 1

        # Overlap: 2 TP (both PERSON and EMAIL overlap), 1 FP (Mars), 0 FN
        assert overlap.tp == 2
        assert overlap.fp == 1
        assert overlap.fn == 0

    def test_leakage_detection(self):
        """Direct information leakage should flag raw sensitive substrings."""
        gt_entities = [
            {"entity_type": "PERSON", "text": "Deepika Menon"},
            {"entity_type": "EMAIL_ADDRESS", "text": "deepika@test.com"},
        ]

        # Case 1: Sanitized text contains no raw values
        clean_text = "Hello PERSON_1, email is EMAIL_ADDRESS_1."
        report_clean = MetricsEvaluator.check_information_leakage(clean_text, gt_entities)
        assert report_clean.leaked_entities_count == 0
        assert report_clean.leakage_rate == 0.0

        # Case 2: Sanitized text leaked the email verbatim
        leaked_text = "Hello PERSON_1, email is deepika@test.com."
        report_leaked = MetricsEvaluator.check_information_leakage(leaked_text, gt_entities)
        assert report_leaked.leaked_entities_count == 1
        assert report_leaked.leakage_rate == 0.5
        assert report_leaked.leaked_instances[0]["entity_type"] == "EMAIL_ADDRESS"

    def test_latency_distribution(self):
        """Latency report accurately computes mean, P50, and P95."""
        samples = [10.0, 20.0, 30.0, 40.0, 100.0]
        report = LatencyReport(samples=samples)

        assert report.mean == 40.0
        assert report.p50 == 30.0
        assert report.p95 >= 40.0

