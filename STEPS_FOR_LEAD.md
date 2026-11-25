# Setup Steps for Lead Developer (Connecting to Local Ollama)

Follow these steps after pulling the repository onto your laptop where **Ollama** is installed.

---

## 1. Check Ollama & Model

The gateway is configured in `gateway/main.py` to connect to:
- **URL:** `http://localhost:11434` (`OLLAMA_BASE_URL`)
- **Model:** `llama3.2:3b` (`OLLAMA_MODEL`)

1. Make sure Ollama is running:
   ```bash
   ollama serve
   ```
   *(If the Ollama desktop app is already running in your system tray, `ollama serve` is already active.)*

2. Pull the default model (or verify you have it):
   ```bash
   ollama pull llama3.2:3b
   ```
   > **Using a different model?** Open `gateway/main.py` and change `OLLAMA_MODEL = "llama3.2:3b"` (line 54) to the exact model name shown in `ollama list`.

---

## 2. Install Backend Dependencies (One-Time)

From the project root folder:

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

*(Optional)* Verify the environment before starting:
```bash
python scripts/verify_setup.py
```
All checks—including **Ollama server reachable**—should pass.

---

## 3. Install Frontend Dependencies (One-Time)

```bash
cd frontend
npm install
cd ..
```

---

## 4. Start Backend & Frontend

Open **two terminals** in the project root:

**Terminal 1 — Start the FastAPI Gateway (Real Ollama Mode):**
```bash
python -m uvicorn gateway.main:app --reload --port 8000
```
> **Important:** Do **not** set `LLMGUARD_MOCK_LLM=1`. Leaving it unset connects the gateway directly to your local Ollama instance.

**Terminal 2 — Start the React + Vite Frontend:**
```bash
cd frontend
npm run dev
```

---

## 5. Verify Everything Works

1. Open **`http://localhost:5173`** in your browser.
2. Check the **top-right status pill**:
   - It should be **green** and say: `Gateway: ok | llama3.2:3b` (with **no** `(mock)` tag).
3. Test with the **Quick Test Prompts** in the left sidebar:
   - **PII Pseudonymization**: Sends your prompt to Ollama with placeholders (`PERSON_1`, `EMAIL_ADDRESS_1`, `PHONE_NUMBER_1`), then restores the real values in Ollama's reply. Check Terminal 1 logs to confirm raw PII was never sent.
   - **Policy Block (403 Credit Card)**: Should immediately return a red **`Blocked by Privacy Policy (403)`** card without calling Ollama.

---

## Troubleshooting

| Symptom | Fix |
| :--- | :--- |
| Top-right badge says `Gateway: degraded` | Ollama is not running on `http://localhost:11434`. Start the Ollama app or run `ollama serve`. |
| Top-right badge says `Gateway Offline` | The FastAPI backend is not running on port `8000` (check Terminal 1). |
| `502` error from Ollama on `/chat` | The model in `OLLAMA_MODEL` (`gateway/main.py`) isn't pulled locally. Run `ollama pull llama3.2:3b` or update `OLLAMA_MODEL` to match `ollama list`. |
| `504` timeout error | First model load on CPU can be slow; retry the message or increase `OLLAMA_TIMEOUT` in `gateway/main.py`. |
