"""
eval/run_experiments.py — End-to-End Evaluation Runner
=========================================================

Runs benchmark experiments against the synthetic Indian dataset.
Measures:
  1. PII Detection Precision, Recall, and F1 (exact and overlap match)
  2. Direct Information Leakage Rate (ground truth vs sanitized text)
  3. Session-consistent Placeholder Assignment
  4. End-to-end Processing Latency (P50, P95, Mean)

Usage:
    python eval/run_experiments.py
    python eval/run_experiments.py --dataset data/synthetic/synthetic_conversations_v1.json --out data/evaluation_report.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

# Ensure project root is in sys.path when executed directly as a script
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from eval.datagen import SyntheticDatasetGenerator
from eval.metrics import (
    ClassificationScores,
    LatencyReport,
    LeakageReport,
    MetricsEvaluator,
)
from gateway.detector import PIIDetector
from gateway.transformer import TextTransformer
from gateway.vault import PIIVault


# ── Formatting Helpers ────────────────────────────────────────

RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
DIM = "\033[2m"


def print_banner(title: str):
    print(f"\n{BOLD}{'='*68}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'='*68}{RESET}\n")


def print_section(title: str):
    print(f"\n{BOLD}{CYAN}── {title} {'─'*(64-len(title))}{RESET}")


# ── Experiment Runner ─────────────────────────────────────────

def run_evaluation(
    dataset_path: Path,
    report_out_path: Optional[Path] = None,
    threshold: float = 0.5,
) -> dict[str, Any]:
    """Execute the full benchmark suite on the dataset."""

    # 1. Load or generate dataset
    if not dataset_path.exists():
        print(f"Dataset not found at {dataset_path}. Generating 10 controlled conversations...")
        gen = SyntheticDatasetGenerator(seed=42)
        conversations = gen.generate_dataset(count=10)
        dataset_path.parent.mkdir(parents=True, exist_ok=True)
        with open(dataset_path, "w", encoding="utf-8") as f:
            json.dump(conversations, f, indent=2, ensure_ascii=False)
        print(f"✓ Generated & saved to {dataset_path}")
    else:
        with open(dataset_path, "r", encoding="utf-8") as f:
            conversations = json.load(f)

    print(f"Loaded {len(conversations)} conversations from {dataset_path.name}")

    # 2. Initialize Gateway Components
    detector = PIIDetector(score_threshold=threshold)
    vault = PIIVault(":memory:")
    transformer = TextTransformer(detector, vault)

    # 3. Aggregators
    total_exact = ClassificationScores()
    total_overlap = ClassificationScores()
    per_type_exact: dict[str, ClassificationScores] = {}
    leakage_tracker = LeakageReport()
    latency_tracker = LatencyReport()

    consistency_checks_passed = 0
    consistency_checks_total = 0

    print_banner("Running Benchmark Experiments on Privacy Gateway")

    # 4. Iterate over conversations & turns
    for conv_idx, conv in enumerate(conversations, 1):
        conv_id = conv["conversation_id"]
        session_id = f"eval_sess_{conv_id}"

        seen_entities_in_session: dict[str, str] = {}  # text -> placeholder

        for turn in conv["turns"]:
            prompt = turn["user_prompt"]
            gt_annotations = [
                ann for ann in turn["annotations"]
                # Only evaluate against entity types that the gateway protects as PII
                if ann["identifier_category"] in ("DIRECT_IDENTIFIER", "QUASI_IDENTIFIER")
            ]

            # Measure latency
            t0 = time.perf_counter()

            # Run detection
            pred_detections = detector.detect(prompt)

            # Run sanitization
            sanitization = transformer.sanitize(
                text=prompt,
                session_id=session_id,
                turn_number=turn["turn_number"],
            )

            elapsed_ms = (time.perf_counter() - t0) * 1000
            latency_tracker.samples.append(elapsed_ms)

            # Evaluate Detection (Exact & Overlap)
            exact_s, overlap_s, type_s = MetricsEvaluator.evaluate_detections(
                ground_truth=gt_annotations,
                predictions=pred_detections,
            )

            total_exact.tp += exact_s.tp
            total_exact.fp += exact_s.fp
            total_exact.fn += exact_s.fn

            total_overlap.tp += overlap_s.tp
            total_overlap.fp += overlap_s.fp
            total_overlap.fn += overlap_s.fn

            for e_type, scores in type_s.items():
                if e_type not in per_type_exact:
                    per_type_exact[e_type] = ClassificationScores()
                per_type_exact[e_type].tp += scores.tp
                per_type_exact[e_type].fp += scores.fp
                per_type_exact[e_type].fn += scores.fn

            # Evaluate Information Leakage
            # Direct identifiers (names, emails, phones, PAN) must NEVER appear in sanitized text
            direct_ids = [
                ann for ann in gt_annotations
                if ann["identifier_category"] == "DIRECT_IDENTIFIER"
            ]
            leak_rep = MetricsEvaluator.check_information_leakage(
                sanitized_text=sanitization.sanitized_text,
                ground_truth_entities=direct_ids,
                conversation_id=conv_id,
                turn_number=turn["turn_number"],
            )
            leakage_tracker.total_ground_truth_entities += leak_rep.total_ground_truth_entities
            leakage_tracker.leaked_entities_count += leak_rep.leaked_entities_count
            leakage_tracker.leaked_instances.extend(leak_rep.leaked_instances)

            # Evaluate Consistency across turns
            for repl in sanitization.replacements:
                # Find matching ground truth text
                orig_match = vault.get_original(session_id, repl.placeholder)
                if orig_match:
                    orig_lower = orig_match.lower().strip()
                    if orig_lower in seen_entities_in_session:
                        consistency_checks_total += 1
                        if seen_entities_in_session[orig_lower] == repl.placeholder:
                            consistency_checks_passed += 1
                    else:
                        seen_entities_in_session[orig_lower] = repl.placeholder

    # 5. Display Formatted Results
    print_section("1. PII Detection Performance")
    print(f"  {'Metric':<22} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10}")
    print(f"  {'-'*58}")
    print(
        f"  {'Exact Match (Micro)':<22} | "
        f"{total_exact.precision:>9.2%} | {total_exact.recall:>9.2%} | {total_exact.f1:>9.2%}"
    )
    print(
        f"  {'Overlap Match (Micro)':<22} | "
        f"{total_overlap.precision:>9.2%} | {total_overlap.recall:>9.2%} | {total_overlap.f1:>9.2%}"
    )

    if per_type_exact:
        print(f"\n  {DIM}Breakdown by Entity Type (Exact Match):{RESET}")
        for e_type, sc in sorted(per_type_exact.items()):
            print(
                f"    {e_type:<20} | P: {sc.precision:>6.1%} | R: {sc.recall:>6.1%} | F1: {sc.f1:>6.1%} (TP={sc.tp}, FN={sc.fn}, FP={sc.fp})"
            )

    print_section("2. Direct Information Leakage")
    leak_rate = leakage_tracker.leakage_rate
    color = GREEN if leak_rate == 0.0 else RED
    print(f"  Total Sensitive Direct Identifiers: {leakage_tracker.total_ground_truth_entities}")
    print(f"  Direct Identifiers Leaked to LLM:   {color}{leakage_tracker.leaked_entities_count}{RESET}")
    print(f"  Direct Leakage Rate:                {color}{leak_rate:.2%}{RESET}")
    if leakage_tracker.leaked_instances:
        print(f"\n  {RED}⚠ Leaked Instances:{RESET}")
        for lk in leakage_tracker.leaked_instances[:5]:
            print(f"    - [{lk['conversation_id']} T{lk['turn']}] {lk['entity_type']}: {lk['leaked_value']}")

    print_section("3. Multi-Turn Placeholder Consistency")
    consistency_rate = (
        consistency_checks_passed / consistency_checks_total
        if consistency_checks_total > 0
        else 1.0
    )
    print(f"  Multi-turn Entity Re-references:   {consistency_checks_total}")
    print(f"  Consistent Placeholder Maintained: {consistency_checks_passed}")
    print(f"  Consistency Accuracy:              {GREEN}{consistency_rate:.2%}{RESET}")

    print_section("4. Processing Latency (ms)")
    print(f"  Processed Turns: {len(latency_tracker.samples)}")
    print(f"  Mean Latency:    {latency_tracker.mean:.1f} ms")
    print(f"  Median (P50):    {latency_tracker.p50:.1f} ms")
    print(f"  P95 Latency:     {latency_tracker.p95:.1f} ms")
    print(f"  P99 Latency:     {latency_tracker.p99:.1f} ms")

    # 6. Build Final Report Object
    report = {
        "dataset": dataset_path.name,
        "conversations_evaluated": len(conversations),
        "total_turns": len(latency_tracker.samples),
        "detection": {
            "exact_match": total_exact.to_dict(),
            "overlap_match": total_overlap.to_dict(),
            "per_entity_type": {k: v.to_dict() for k, v in per_type_exact.items()},
        },
        "leakage": leakage_tracker.to_dict(),
        "consistency": {
            "total_re_references": consistency_checks_total,
            "consistent_matches": consistency_checks_passed,
            "consistency_rate": round(consistency_rate, 4),
        },
        "latency": latency_tracker.to_dict(),
    }

    if report_out_path:
        report_out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(report_out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\n{GREEN}✓ Full evaluation report saved to: {report_out_path.resolve()}{RESET}\n")

    return report


def main():
    parser = argparse.ArgumentParser(description="Run benchmark evaluation against synthetic dataset.")
    parser.add_argument(
        "--dataset",
        type=str,
        default="data/synthetic/synthetic_conversations_v1.json",
        help="Path to dataset JSON",
    )
    parser.add_argument(
        "--out",
        type=str,
        default="data/evaluation_report.json",
        help="Path to save evaluation report",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Presidio confidence score threshold",
    )
    args = parser.parse_args()

    run_evaluation(
        dataset_path=Path(args.dataset),
        report_out_path=Path(args.out),
        threshold=args.threshold,
    )


if __name__ == "__main__":
    main()
