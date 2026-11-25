# LLMGuard — Policy-Aware LLM Privacy Gateway

A privacy-aware FastAPI gateway and React + Vite web interface that sits between users and a local LLM (**Ollama**). LLMGuard detects sensitive information (PII) in user prompts, enforces configurable YAML privacy policies, sanitizes messages before they leave the gateway, and inspects LLM responses before restoring placeholders.

> **Core Guarantee:** Raw PII never leaves the gateway—never sent to the LLM, never stored in conversation history, and never written to audit logs.

---

## Architecture & Request Flow

```text
User Prompt (React UI)
   │
   ▼
1. PIIDetector        (Presidio + spaCy + custom Indian PAN / Aadhaar / +91 phone recognizers)
   │
   ▼
2. PolicyEngine       (policies/default.yaml: ALLOW, PSEUDONYMIZE, GENERALIZE, REDACT, BLOCK)
   │  └─ BLOCK / >15 entities ──▶ 403 Forbidden + Audit Event
   ▼
3. AliasResolver + TextTransformer
   │  └─ Replaces PII right-to-left with session-consistent placeholders (e.g. PERSON_1)
   ▼
4. PIIVault (SQLite)  (Session-isolated storage for original ↔ placeholder + aliases)
   │
   ▼
5. Ollama (/api/chat) (Receives ONLY sanitized conversation history)
   │
   ▼
6. ResponseInspector  (Validates placeholders + re-scans output for newly generated PII)
   │
   ▼
7. TextTransformer.restore() ──▶ Restores safe placeholders ──▶ User Reply
```

---

## Project Structure

```text
.
├── gateway/                  # FastAPI backend & privacy pipeline
│   ├── main.py               # API endpoints (/chat, /health, /session/{id}), CORS & mock mode
│   ├── detector.py           # Presidio Analyzer + custom Indian PII recognizers
│   ├── policy.py             # PolicyEngine & k-anonymity Generalizer
│   ├── resolver.py           # Cross-turn person alias resolution
│   ├── transformer.py        # Sanitize & restore text with overlap handling
│   ├── vault.py              # Session-isolated SQLite vault (privacy_vault.db)
│   ├── inspector.py          # LLM output placeholder & new-PII inspector
│   └── audit.py              # Zero-PII JSONL security audit logger (logs/audit.jsonl)
├── frontend/                 # React + Vite web interface
│   ├── src/App.jsx           # Chat UI, session management, health status & quick test prompts
│   ├── src/api.js            # Gateway API client
│   └── vite.config.js        # Dev proxy (/api -> http://localhost:8000)
├── policies/
│   └── default.yaml          # Default privacy policy rules & thresholds
├── eval/                     # Synthetic dataset generator, metrics & benchmark runner
├── data/                     # Synthetic conversations & evaluation reports
├── tests/                    # Unit & integration test suite
├── scripts/                  # Setup verification & CLI demo scripts
└── docs/
    └── threat_model.md       # Threat model, assets & mitigations
```

---

## Prerequisites

- **Python** `>= 3.10`
- **Node.js** `>= 18` and **npm**
- **Ollama** (for running with a real local LLM)

---

## Quick Start (With Real Ollama)

### 1. Start Ollama & Pull the Model

The gateway defaults to `llama3.2:3b` at `http://localhost:11434` (configurable in `gateway/main.py`).

```bash
ollama pull llama3.2:3b
ollama serve
```

> If you want to use a different Ollama model, update `OLLAMA_MODEL` in `gateway/main.py`.

### 2. Install Backend Dependencies (One-Time)

From the project root:

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

### 3. Install Frontend Dependencies (One-Time)

```bash
cd frontend
npm install
cd ..
```

### 4. Run Backend & Frontend

**Terminal 1 — Start the FastAPI Gateway:**

```bash
python -m uvicorn gateway.main:app --reload --port 8000
```

**Terminal 2 — Start the React + Vite UI:**

```bash
cd frontend
npm run dev
```

Open **`http://localhost:5173`** in your browser.

- The top-right status badge should turn green and show **`Gateway: ok | llama3.2:3b`**.
- Use the **Quick Test Prompts** in the left sidebar to test normal prompts, PII pseudonymization/restoration, and `403` policy blocks (e.g., credit card numbers).

---

## Frontend Development Without Ollama (Mock LLM Mode)

If you want to run and test the UI and full PII pipeline without Ollama installed, enable `LLMGUARD_MOCK_LLM=1` before starting the backend:

- **Windows Command Prompt (`cmd.exe`):**
  ```bat
  set LLMGUARD_MOCK_LLM=1 && python -m uvicorn gateway.main:app --reload --port 8000
  ```
- **Windows PowerShell:**
  ```powershell
  $env:LLMGUARD_MOCK_LLM="1"; python -m uvicorn gateway.main:app --reload --port 8000
  ```
- **macOS / Linux:**
  ```bash
  LLMGUARD_MOCK_LLM=1 python -m uvicorn gateway.main:app --reload --port 8000
  ```

In mock mode, `POST /chat` still runs real Presidio PII detection, policy blocking (`403`), vault mapping, and restoration, while returning a mock LLM reply.

---

## API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/chat` | Accepts `{ "session_id", "message" }`, runs the privacy pipeline, and returns `{ "session_id", "reply", "pii_detected", "entities_found", "processing_time_ms" }`. Returns `403` if blocked by policy. |
| `GET` | `/health` | Returns gateway, detector, vault, and Ollama reachability status. |
| `DELETE` | `/session/{session_id}` | Wipes all vault mappings and conversation history for a session. |

---

## Verification & Tests

Verify environment setup:

```bash
python scripts/verify_setup.py
```

Run the test suite:

```bash
python -m pytest
```
