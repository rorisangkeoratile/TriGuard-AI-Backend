# TriGuard AI — Backend

**Trace the fake. Protect the truth.**

FastAPI backend for TriGuard AI, a "Truecaller for AI scams" PWA that helps everyday South Africans check
voices, messages, emails, links and phone numbers **before** they pay or share personal information.

## Features

| Feature | Endpoint | How it works |
|---|---|---|
| 🎙️ **Voice-clone check** (MVP) | `POST /api/v1/voice/analyze` | wav2vec2 deepfake-audio model + acoustic signals + Whisper transcript checked for scam tactics + quick "what did the caller ask?" answers |
| 💬 Scam message check | `POST /api/v1/messages/analyze` | SA-specific rule engine (offline) + Claude explanation in the user's language |
| 📸 Screenshot check | `POST /api/v1/messages/screenshot` | Claude reads a screenshot of any chat and analyses it |
| 📧 Email phishing check | `POST /api/v1/email/analyze` | SPF/DKIM/DMARC failures, spoofed bank names, Reply-To tricks, lying links, dangerous attachments |
| 🔗 Link check | `POST /api/v1/links/check` | Look-alike bank/government domains, shorteners, punycode, risky TLDs, optional Google Safe Browsing |
| 📞 Number lookup (Truecaller-style) | `GET /api/v1/numbers/lookup?number=` | Community scam reports per number |
| 🚩 Report a number | `POST /api/v1/numbers/report` | Anonymous, one report per device per number per day |
| 📈 Trending scam numbers | `GET /api/v1/numbers/trending` | Most-reported numbers in the last 30 days |
| ⚙️ Capabilities | `GET /api/v1/capabilities` | Lets the PWA show which features are live |

Every analysis returns the same shape, so the frontend can use **one result screen**:

```json
{
  "risk_level": "safe | low | medium | high | critical",
  "risk_score": 0,
  "headline": "This looks like a scam",
  "summary": "Plain-language explanation…",
  "indicators": [{ "code": "otp_request", "title": "…", "detail": "…", "weight": 0.75, "source": "rules" }],
  "advice": ["Hang up and call back on a number you trust", "…"],
  "disclaimer": "TriGuard gives risk indicators, not proof…"
}
```

## Privacy by design (POPIA)

- Audio, screenshots and messages are analysed **in memory and never stored**.
- Only **reported phone numbers** (and an optional short comment) are stored, with a hashed reporter id.
- TriGuard does **not** read WhatsApp, SMS or calls automatically. Users choose what to check:
  record/upload, paste, or **share into TriGuard** from any app (PWA Web Share Target).

## Quick start

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements.txt
copy .env.example .env   # add ANTHROPIC_API_KEY (optional but recommended)
uvicorn app.main:app --reload --port 8000
```

Open http://localhost:8000/docs for interactive API docs.

The first start downloads the voice model (~380 MB) and Whisper base (~290 MB) from Hugging Face into
your cache; the API is usable immediately and `/api/v1/capabilities` shows when the models are ready.

**Slow or unreliable internet?** Download the voice model once with a resumable download and point the
app at the local folder:

```bash
mkdir -p models/deepfake-audio && cd models/deepfake-audio
for f in config.json preprocessor_config.json model.safetensors; do
  curl -L -C - --retry 10 -o $f https://huggingface.co/mo-thecreator/Deepfake-audio-detection/resolve/main/$f
done
```

then set `VOICE_MODEL_ID=models/deepfake-audio` in `.env` (and `TRANSCRIPTION_MODEL_ID=openai/whisper-tiny`
for a smaller ~150 MB transcription model).

Without an `ANTHROPIC_API_KEY` everything still works using the offline rule engine (screenshot reading
is the only feature that needs it).

### Demo numbers (seeded, fictional)

| Number | Seeded reports |
|---|---|
| `071 000 0001` | "Hi Mom new number" + AI voice clone (critical) |
| `082 000 0002` | Fake bank / OTP |
| `061 000 0003` | Fake job |
| `011 000 0004` | Spam sales calls |

## Tests

```powershell
pytest -q
```

## Project layout

```
app/
  main.py               FastAPI app, CORS, startup model loading, capabilities
  config.py             Settings (env / .env)
  schemas.py            Request/response models
  db.py                 SQLite store for community number reports
  routers/              voice, messages (+ email, screenshot, links), numbers
  services/
    audio.py            Decode webm/opus/m4a/mp3/wav -> 16 kHz mono (PyAV, no ffmpeg needed)
    voice_detector.py   Deepfake model, Whisper, acoustic features
    voice_analysis.py   Voice pipeline -> one verdict
    scam_rules.py       South African scam pattern rules + entity extraction
    llm.py              Claude analysis (structured output, multilingual, vision)
    message_analysis.py Rules + links + Claude -> one verdict
    email_analysis.py   Header / sender / link / attachment checks
    links.py            URL heuristics + Google Safe Browsing
    numbers.py          Number normalisation + reputation
    risk.py             Scoring, levels, headlines, advice
```

## Limitations (say this to the judges)

- Results are **risk indicators, not proof**. Open-source deepfake detectors can be fooled by new
  voice-cloning tools and by heavy compression, which is why TriGuard also checks *what* was said and
  *how* the caller behaves — a cloned voice still has to ask for money, urgently and secretly.
- Live-call monitoring isn't possible from a web app on WhatsApp/regular calls; it's a future native
  Android feature (call-screening API) or a partnership with networks/banks.
