# LLMGuard — Policy-Aware LLM Privacy Gateway

A privacy gateway that detects sensitive information in user prompts, applies
configurable privacy policies, sanitizes messages before sending them to an LLM,
and inspects generated responses for information leakage.

## Architecture Overview

```
User Prompt
    │
    ▼
┌──────────┐    ┌──────────────┐    ┌───────────┐
│ Detector │───▶│ Transformer  │───▶│   Vault   │
│(Presidio)│    │(Sanitization)│    │ (SQLite)  │
└──────────┘    └──────┬───────┘    └───────────┘
                       │
                       ▼
               ┌──────────────┐
               │   Ollama     │
               │ (Llama 3.2)  │
               └──────┬───────┘
                       │
                       ▼
               ┌──────────────┐    ┌───────────┐
               │  Inspector   │───▶│   Audit   │
               │(Response QA) │    │  (Logs)   │
               └──────┬───────┘    └───────────┘
                       │
                       ▼
              Sanitized Response
```

## Quick Start

```powershell
# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
python -m spacy download en_core_web_lg

# Ensure Ollama is running with Llama 3.2
ollama pull llama3.2:3b

# Start the gateway
uvicorn gateway.main:app --reload --port 8000
```

## Project Status

- [x] Phase 1: Environment setup
- [ ] Phase 2: PII detection
- [ ] Phase 3: SQLite vault and sanitization
- [ ] Phase 4: FastAPI + Ollama integration
- [ ] Phase 5: Audit and output inspection

## License

Research project — not for production use.

