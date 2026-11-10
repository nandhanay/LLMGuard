"""
scripts/test_live_chat.py — Test Live FastAPI + Ollama Pipeline
================================================================

Sends a test conversation to the running FastAPI gateway
and prints the full pipeline flow.

Prerequisites:
  1. Ollama running:       ollama run llama3.2:3b "hello"
  2. Gateway running:      uvicorn gateway.main:app --port 8000
  3. Run this script:      python scripts/test_live_chat.py
"""

import sys
import time
import httpx

RESET = "\033[0m"
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"

BASE_URL = "http://localhost:8000"


def header(title: str):
    print(f"\n{BOLD}{'─'*60}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'─'*60}{RESET}")


def main():
    header("LLMGuard — Live End-to-End Test")

    # 1. Health check
    print("\n  Checking gateway health...")
    try:
        resp = httpx.get(f"{BASE_URL}/health", timeout=5.0)
        data = resp.json()
        print(f"  Gateway status:    {GREEN}{data['status']}{RESET}")
        print(f"  Ollama reachable:  {GREEN if data['ollama_reachable'] else RED}{data['ollama_reachable']}{RESET}")
        print(f"  Ollama model:      {data['ollama_model']}")

        if not data["ollama_reachable"]:
            print(f"\n  {YELLOW}⚠ Ollama is not running! Start it with:{RESET}")
            print(f"    ollama pull llama3.2:3b")
            print(f"    ollama serve")
            return
    except httpx.ConnectError:
        print(f"\n  {RED}✗ Gateway is not running at {BASE_URL}{RESET}")
        print(f"  Start it with:")
        print(f"    uvicorn gateway.main:app --port 8000")
        return

    # 2. Multi-turn chat
    session_id = f"test-{int(time.time())}"
    print(f"\n  Session ID: {BOLD}{session_id}{RESET}")

    messages = [
        "Hi! My name is Rahul Sharma. I am a software engineer from Bangalore.",
        "Can you write a short professional bio for me?",
        "Also, my email is rahul.sharma@techcorp.in if you need to mention it.",
        "Thanks! By the way, what was my name again?",
    ]

    for i, msg in enumerate(messages, 1):
        header(f"Turn {i}")
        print(f"  {DIM}User prompt:{RESET}  {msg}\n")

        t0 = time.perf_counter()
        resp = httpx.post(
            f"{BASE_URL}/chat",
            json={"session_id": session_id, "message": msg},
            timeout=120.0,
        )
        elapsed = (time.perf_counter() - t0) * 1000

        if resp.status_code != 200:
            print(f"  {RED}Error {resp.status_code}:{RESET} {resp.text}")
            continue

        data = resp.json()
        print(f"  {DIM}PII detected:{RESET}  {GREEN if data['pii_detected'] else DIM}{data['pii_detected']}{RESET} "
              f"({data['entities_found']} entities)")
        print(f"  {DIM}Latency:{RESET}       {data['processing_time_ms']:.0f} ms "
              f"(gateway) / {elapsed:.0f} ms (total)")
        print(f"\n  {GREEN}Assistant reply:{RESET}")
        print(f"  {data['reply']}\n")

    # 3. Clean up
    header("Cleanup")
    resp = httpx.delete(f"{BASE_URL}/session/{session_id}")
    del_data = resp.json()
    print(f"  Deleted {del_data['mappings_deleted']} vault mappings for {session_id}")
    print(f"  {GREEN}✓ Test complete.{RESET}\n")


if __name__ == "__main__":
    main()

