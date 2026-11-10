"""
scripts/demo_transformer.py — Sanitization & Vault Demo
==========================================================

Demonstrates end-to-end PII sanitization:
  Detect → Replace with placeholders → Store in vault → Restore

Usage:  python scripts/demo_transformer.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gateway.detector import PIIDetector
from gateway.vault import PIIVault
from gateway.transformer import TextTransformer

RESET = "\033[0m"
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"


def header(title: str):
    print(f"\n{BOLD}{'─'*60}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'─'*60}{RESET}")


def main():
    header("LLMGuard — Sanitization & Vault Demo")

    print(f"\n  Initializing Detector + Vault + Transformer...")
    detector = PIIDetector(score_threshold=0.4)
    vault = PIIVault(":memory:")
    transformer = TextTransformer(detector, vault)
    print(f"  {GREEN}✓ Ready{RESET}\n")

    session = "demo-session-001"

    # ── Multi-turn conversation ──────────────────────────────

    turns = [
        "Hi, my name is Rahul Sharma. I'm a student at IIT Delhi.",
        "My email is rahul.sharma@gmail.com and phone is +91-9876543210.",
        "I'm working with my classmate Priya Patel on a research project.",
        "Priya's email is priya.patel@iitd.ac.in. Rahul Sharma is the lead.",
        "Please send the report to rahul.sharma@gmail.com by Friday.",
    ]

    all_results = []

    for i, turn_text in enumerate(turns, 1):
        header(f"Turn {i}")
        print(f"  {DIM}Input:{RESET}  {turn_text}\n")

        result = transformer.sanitize(
            text=turn_text,
            session_id=session,
            turn_number=i,
        )
        all_results.append(result)

        print(f"  {GREEN}Output:{RESET} {result.sanitized_text}\n")

        # Show replacements
        if result.replacements:
            for r in result.replacements:
                status = f"{YELLOW}reused{RESET}" if r.was_existing else f"{CYAN}new{RESET}"
                print(
                    f"    {r.entity_type:<20} → {r.placeholder:<20} "
                    f"[{status}]  score={r.score:.2f}"
                )
        else:
            print(f"    {DIM}No PII detected{RESET}")

        # Audit summary
        summary = result.get_audit_summary()
        print(f"\n  {DIM}Audit (safe to log): {summary}{RESET}")

    # ── Session vault contents ───────────────────────────────

    header("Vault Contents (Session: demo-session-001)")
    mappings = vault.get_all_mappings(session)
    print(f"\n  {BOLD}Total mappings: {len(mappings)}{RESET}\n")

    for m in mappings:
        print(
            f"    {m['placeholder']:<22} → {m['original_value']:<30} "
            f"(type={m['entity_type']}, turn={m['turn_number']})"
        )

    # ── Session stats (safe to log) ──────────────────────────

    header("Session Stats (safe to log — no PII)")
    stats = vault.get_session_stats(session)
    for entity_type, count in stats.items():
        print(f"    {entity_type}: {count}")

    # ── Restoration demo ─────────────────────────────────────

    header("Placeholder Restoration Demo")
    llm_response = (
        "Sure, PERSON_1! I've noted your request. "
        "I'll send the project update to EMAIL_ADDRESS_1 "
        "and CC PERSON_2 at EMAIL_ADDRESS_2."
    )
    print(f"\n  {DIM}LLM Response:{RESET}")
    print(f"  {llm_response}\n")

    restored = transformer.restore(llm_response, session_id=session)
    print(f"  {GREEN}Restored:{RESET}")
    print(f"  {restored}\n")

    # Selective restoration
    print(f"  {YELLOW}Selective (names only):{RESET}")
    names_only = [m["placeholder"] for m in mappings if m["entity_type"] == "PERSON"]
    selective = transformer.restore(
        llm_response, session_id=session,
        placeholders_to_restore=names_only,
    )
    print(f"  {selective}\n")

    # ── Session isolation demo ───────────────────────────────

    header("Session Isolation Demo")
    other_session = "other-session-999"
    vault.store(other_session, "PERSON", "PERSON_1", "Vikram Deshmukh")

    print(f"\n  Session '{session}' PERSON_1 → {vault.get_original(session, 'PERSON_1')}")
    print(f"  Session '{other_session}' PERSON_1 → {vault.get_original(other_session, 'PERSON_1')}")
    print(f"\n  {GREEN}✓ Sessions are fully isolated!{RESET}")

    # ── Cleanup ──────────────────────────────────────────────

    header("Cleanup")
    deleted = vault.delete_session(session)
    print(f"\n  Deleted {deleted} mappings from session '{session}'")
    remaining = vault.get_all_mappings(session)
    print(f"  Remaining: {len(remaining)} mappings")
    print(f"  {GREEN}✓ Session data wiped.{RESET}\n")

    vault.close()


if __name__ == "__main__":
    main()

