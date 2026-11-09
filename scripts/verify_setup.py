"""
scripts/verify_setup.py — Phase 1 Environment Verification
=============================================================

Run this script AFTER installing all dependencies to verify that
every component of the LLMGuard environment is working correctly.

Usage:
    python scripts/verify_setup.py
"""

import sys
import importlib
import subprocess
import json

RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BOLD = "\033[1m"

passed = 0
failed = 0
warnings = 0


def check(label: str, success: bool, detail: str = "", warn: bool = False):
    """Print a check result."""
    global passed, failed, warnings
    if success:
        print(f"  {GREEN}✓{RESET} {label}" + (f"  ({detail})" if detail else ""))
        passed += 1
    elif warn:
        print(f"  {YELLOW}⚠{RESET} {label}" + (f"  ({detail})" if detail else ""))
        warnings += 1
    else:
        print(f"  {RED}✗{RESET} {label}" + (f"  ({detail})" if detail else ""))
        failed += 1


def main():
    global passed, failed, warnings

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  LLMGuard — Phase 1 Environment Verification{RESET}")
    print(f"{BOLD}{'='*60}{RESET}\n")

    # ── 1. Python version ──────────────────────────────────────
    print(f"{BOLD}[1/7] Python{RESET}")
    v = sys.version_info
    check(
        f"Python {v.major}.{v.minor}.{v.micro}",
        v >= (3, 10),
        "Requires >= 3.10" if v < (3, 10) else "",
    )

    # ── 2. Core packages ──────────────────────────────────────
    print(f"\n{BOLD}[2/7] Python Packages{RESET}")
    packages = {
        "fastapi": "fastapi",
        "uvicorn": "uvicorn",
        "pydantic": "pydantic",
        "presidio_analyzer": "presidio_analyzer",
        "presidio_anonymizer": "presidio_anonymizer",
        "spacy": "spacy",
        "httpx": "httpx",
        "yaml": "yaml (PyYAML)",
        "faker": "faker",
        "pandas": "pandas",
        "pytest": "pytest",
        "aiosqlite": "aiosqlite",
        "dotenv": "python-dotenv",
    }
    for import_name, display_name in packages.items():
        try:
            mod = importlib.import_module(import_name)
            ver = getattr(mod, "__version__", "installed")
            check(f"{display_name}", True, ver)
        except ImportError:
            check(f"{display_name}", False, "not installed")

    # ── 3. spaCy model ────────────────────────────────────────
    print(f"\n{BOLD}[3/7] spaCy NLP Model{RESET}")
    try:
        import spacy
        nlp = spacy.load("en_core_web_lg")
        check("en_core_web_lg", True, f"{len(nlp.pipe_names)} pipeline components")
    except OSError:
        check("en_core_web_lg", False, "Model not found. Run: python -m spacy download en_core_web_lg")
    except ImportError:
        check("en_core_web_lg", False, "spaCy not installed")

    # ── 4. Presidio quick test ─────────────────────────────────
    print(f"\n{BOLD}[4/7] Presidio Analyzer Quick Test{RESET}")
    try:
        from presidio_analyzer import AnalyzerEngine
        analyzer = AnalyzerEngine()
        results = analyzer.analyze(
            text="My name is Rahul Sharma and my email is rahul@example.com",
            language="en",
        )
        entity_types = {r.entity_type for r in results}
        check(
            "Presidio detection works",
            len(results) > 0,
            f"Detected: {', '.join(sorted(entity_types))}",
        )
    except Exception as e:
        check("Presidio detection works", False, str(e))

    # ── 5. SQLite ─────────────────────────────────────────────
    print(f"\n{BOLD}[5/7] SQLite{RESET}")
    try:
        import sqlite3
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, val TEXT)")
        conn.execute("INSERT INTO test VALUES (1, 'ok')")
        row = conn.execute("SELECT val FROM test WHERE id = 1").fetchone()
        conn.close()
        check("SQLite in-memory test", row[0] == "ok", f"sqlite3 v{sqlite3.sqlite_version}")
    except Exception as e:
        check("SQLite in-memory test", False, str(e))

    # ── 6. Ollama ─────────────────────────────────────────────
    print(f"\n{BOLD}[6/7] Ollama{RESET}")
    try:
        result = subprocess.run(
            ["ollama", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        version_str = result.stdout.strip() or result.stderr.strip()
        check("Ollama CLI", result.returncode == 0, version_str)
    except FileNotFoundError:
        check("Ollama CLI", False, "ollama not found in PATH")
    except Exception as e:
        check("Ollama CLI", False, str(e))

    # Check if Ollama server is reachable
    try:
        import httpx
        resp = httpx.get("http://localhost:11434/api/tags", timeout=5)
        if resp.status_code == 200:
            models = resp.json().get("models", [])
            model_names = [m["name"] for m in models]
            has_llama = any("llama3.2" in name for name in model_names)
            check(
                "Ollama server reachable",
                True,
                f"{len(models)} model(s) available",
            )
            if has_llama:
                check("llama3.2 model", True, "available")
            else:
                check(
                    "llama3.2 model", False,
                    f"Not found. Available: {', '.join(model_names) or 'none'}. "
                    "Run: ollama pull llama3.2:3b",
                    warn=True,
                )
        else:
            check("Ollama server reachable", False, f"HTTP {resp.status_code}", warn=True)
    except Exception:
        check(
            "Ollama server reachable", False,
            "Cannot connect to http://localhost:11434. Is Ollama running?",
            warn=True,
        )

    # ── 7. Project structure ──────────────────────────────────
    print(f"\n{BOLD}[7/7] Project Structure{RESET}")
    from pathlib import Path
    project_root = Path(__file__).resolve().parent.parent
    expected_files = [
        "gateway/__init__.py",
        "gateway/main.py",
        "gateway/detector.py",
        "gateway/transformer.py",
        "gateway/vault.py",
        "gateway/inspector.py",
        "gateway/audit.py",
        "gateway/policy.py",
        "gateway/resolver.py",
        "eval/__init__.py",
        "tests/__init__.py",
        "policies/default.yaml",
        "requirements.txt",
        "README.md",
    ]
    for rel_path in expected_files:
        full_path = project_root / rel_path
        check(rel_path, full_path.exists())

    # ── Summary ───────────────────────────────────────────────
    print(f"\n{BOLD}{'='*60}{RESET}")
    total = passed + failed + warnings
    print(f"  {GREEN}Passed: {passed}{RESET}  |  {RED}Failed: {failed}{RESET}  |  {YELLOW}Warnings: {warnings}{RESET}  |  Total: {total}")

    if failed == 0 and warnings == 0:
        print(f"\n  {GREEN}{BOLD}✓ All checks passed! Ready for Phase 2.{RESET}\n")
    elif failed == 0:
        print(f"\n  {YELLOW}{BOLD}⚠ Passed with warnings. Review items above.{RESET}\n")
    else:
        print(f"\n  {RED}{BOLD}✗ Some checks failed. Fix the issues above before proceeding.{RESET}\n")

    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()

