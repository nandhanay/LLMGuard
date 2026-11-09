"""
scripts/demo_detector.py — Interactive PII Detection Demo
============================================================

Run this to see Presidio detection in action with sample texts.
Usage:  python scripts/demo_detector.py

This script demonstrates:
- Detection of names, emails, phone numbers, and other PII
- Confidence scores and character positions
- Audit-safe summary output (no PII leaked)
- Indian context detection
"""

import sys
import time

# Ensure project root is importable
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gateway.detector import PIIDetector

RESET = "\033[0m"
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"


def print_header(title: str):
    print(f"\n{BOLD}{'─'*60}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'─'*60}{RESET}")


def print_detections(text: str, results: list, elapsed_ms: float):
    """Pretty-print detection results with highlighted spans."""
    print(f"\n  {DIM}Input:{RESET}  {text}")
    print(f"  {DIM}Time:{RESET}   {elapsed_ms:.1f} ms")
    print(f"  {DIM}Found:{RESET}  {len(results)} entities\n")

    if not results:
        print(f"  {GREEN}No PII detected.{RESET}\n")
        return

    # Print each detection
    for i, r in enumerate(results, 1):
        color = {
            "PERSON": CYAN,
            "EMAIL_ADDRESS": YELLOW,
            "PHONE_NUMBER": GREEN,
            "CREDIT_CARD": RED,
            "LOCATION": "\033[95m",  # magenta
        }.get(r.entity_type, RESET)

        print(
            f"  {BOLD}{i}.{RESET} "
            f"{color}{r.entity_type:<20}{RESET} "
            f"'{r.text}'"
            f"  {DIM}span=({r.start},{r.end})  score={r.score:.2f}{RESET}"
        )

    # Show the text with PII highlighted
    print(f"\n  {DIM}Annotated:{RESET}", end="  ")
    prev_end = 0
    for r in sorted(results, key=lambda x: x.start):
        # Print text before this entity
        print(text[prev_end:r.start], end="")
        # Print the entity highlighted
        print(f"{RED}[{r.entity_type}]{RESET}", end="")
        prev_end = r.end
    print(text[prev_end:])  # Print remaining text
    print()


def main():
    print_header("LLMGuard — PII Detection Demo")
    print(f"\n  Initializing Presidio + spaCy engine...")

    start = time.perf_counter()
    detector = PIIDetector(score_threshold=0.4)
    init_time = (time.perf_counter() - start) * 1000
    print(f"  {GREEN}✓ Engine ready in {init_time:.0f} ms{RESET}")
    print(f"  {DIM}{detector}{RESET}")

    # ── Test cases ────────────────────────────────────────────

    test_cases = [
        (
            "Basic — Name + Email",
            "My name is Rahul Sharma and my email is rahul.sharma@gmail.com."
        ),
        (
            "Multiple entity types",
            "Hi, I'm Priya Patel. Call me at +91-9876543210 or email priya@company.com."
        ),
        (
            "Indian context — Multi-person",
            "Ananya Krishnamurthy and Vikram Deshmukh discussed the project "
            "with their manager Deepak Nair in the Bangalore office."
        ),
        (
            "Credit card & IP",
            "Please charge card 4111-1111-1111-1111 and whitelist IP 192.168.1.100."
        ),
        (
            "No PII",
            "The weather in November is usually pleasant with clear skies."
        ),
        (
            "Mixed sensitive info",
            "Dear Mr. Suresh Kumar, your appointment at Apollo Hospital Chennai "
            "is confirmed for tomorrow. Contact: suresh.kumar@hospital.org, "
            "phone: +91-44-2345-6789."
        ),
        (
            "Gradual disclosure (multi-turn simulation)",
            "I'm a student at IIT Madras. My registration number is CS21B042. "
            "You can reach my advisor Prof. Ramesh Babu at ramesh@iitm.ac.in."
        ),
    ]

    for title, text in test_cases:
        print_header(title)

        t0 = time.perf_counter()
        results = detector.detect(text)
        elapsed = (time.perf_counter() - t0) * 1000

        print_detections(text, results, elapsed)

        # Show audit-safe summary
        summary = detector.detect_summary(text)
        print(f"  {DIM}Audit summary (safe to log):{RESET}")
        print(f"  {DIM}  entity_counts: {summary['entity_counts']}{RESET}")
        print(f"  {DIM}  total: {summary['total_entities']}, "
              f"text_length: {summary['text_length']}{RESET}")

    # ── Interactive mode ──────────────────────────────────────
    print_header("Interactive Mode — Type your own text")
    print(f"  {DIM}Type a sentence and press Enter to scan for PII.{RESET}")
    print(f"  {DIM}Type 'quit' or 'exit' to stop.{RESET}\n")

    while True:
        try:
            user_input = input(f"  {CYAN}>{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if user_input.lower() in ("quit", "exit", "q"):
            break
        if not user_input:
            continue

        t0 = time.perf_counter()
        results = detector.detect(user_input)
        elapsed = (time.perf_counter() - t0) * 1000
        print_detections(user_input, results, elapsed)

    print(f"\n  {GREEN}Done!{RESET}\n")


if __name__ == "__main__":
    main()

