# TriGuard AI — Backend

**Trace the fake. Protect the truth.**

FastAPI backend for TriGuard AI, a "Truecaller for AI scams" PWA that helps everyday South Africans check
voices, messages, emails, links and phone numbers **before** they pay or share personal information.

## Features

| Feature | Endpoint | How it works |
|---|---|---|
| 🎙️ **Voice-clone check** (MVP) | `POST /api/v1/voice/analyze` | wav2vec2 deepfake-audio model + acoustic signals + Whisper transcript checked for scam tactics + quick "what did the caller ask?" answers |
| 💬 Scam message check | `POST /api/v1/messages/analyze` | SA-specific rule engine (offline) + AI explanation (Gemini, free) in the user's language |
| 📸 Screenshot check | `POST /api/v1/messages/screenshot` | The AI model reads a screenshot of any chat and analyses it |
| 📧 Email phishing check | `POST /api/v1/email/analyze` | SPF/DKIM/DMARC failures, spoofed bank names, Reply-To tricks, lying links, dangerous attachments |
| 🔗 Link check | `POST /api/v1/links/check` | Look-alike bank/government domains, shorteners, punycode, risky TLDs, optional Google Safe Browsing |
| 📞 Number lookup (Truecaller-style) | `GET /api/v1/numbers/lookup?number=` | Community scam reports per number |
| 🚩 Report a number | `POST /api/v1/numbers/report` | Anonymous, one report per device per number per day |
| 📈 Trending scam numbers | `GET /api/v1/numbers/trending` | Most-reported numbers in the last 30 days |
| 📊 Insights | `GET /api/v1/insights` | Checks today, scams detected, reports this week, top scam types, most-reported numbers |
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

## All 11 official languages

Every endpoint takes a `language` (`en, af, zu, xh, nso, ts, st, tn, ss, ve, nr`). Messages, emails and
screenshots also accept `auto`, which answers in the message's own language. Results include `language`
(and `detected_language` for messages).

| | en | af | zu | xh | nso | ts | st | tn | ss | ve | nr |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Understand messages / emails (AI) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Results in this language (AI) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Offline scam keywords (no API key) | ✅ | basic | basic | basic | basic | basic | basic | basic | basic | basic | basic |
| Voice-clone check (language-independent) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Voice-note transcription | Whisper | Whisper | MMS* / AI† | MMS* / AI† | MMS* / AI† | MMS* / AI† | AI† | AI† | AI† | AI† | AI† |

† Experimental: Gemini transcribes the voice note when no local model covers the language. Quality for
these languages is unmeasured - test with native speakers before relying on it in the demo.

\* Meta MMS is a 3.9 GB opt-in download (`MMS_ENABLED=true`). For voice notes in languages without
transcription, TriGuard still runs the voice-clone check and asks the user quick questions about the call
(asked for money? urgent? secret?), which work in every language.

Offline keywords cover the most common scam phrases only and should be reviewed by native speakers
(`app/services/scam_rules.py`, `ML`). Without an API key, results are in English.

`GET /api/v1/capabilities` returns this table live, so the PWA can show it in its language picker.

## AI provider

| Provider | Cost | Setting |
|---|---|---|
| Google Gemini (`gemini-3.8-flash`) | **Free tier** (sign in with a Google account) | `GEMINI_API_KEY` |
| Anthropic Claude (`claude-opus-5-5`) | Paid | `ANTHROPIC_API_KEY` |

`LLM_PROVIDER=auto` uses whichever key is set. Swap providers without changing any code.

> ⚠️ On Gemini's **free tier, Google may use submitted content to improve its products**. Fine for a
> hackathon demo with sample scam messages; for real users, switch to a paid tier (Gemini or Claude),
> where content isn't used for training, and say so in the privacy policy.

## Privacy by design (POPIA)

- Audio, screenshots and messages are analysed **in memory and never stored**.
- Only **reported phone numbers** (and an optional short comment) are stored, with a hashed reporter id.
- For the Insights screen, each check adds an anonymous counter row (`kind`, `risk_level`, `scam_type`,
  time) - never the message, audio or number that was checked.
- A user's **check history stays on their phone** (browser storage in the PWA), not on the server.
- ID, card, bank account and phone numbers and email names are **masked before text is sent to the AI
  provider** and before report comments are saved (`app/services/privacy.py`). Fake domains and amounts are
  kept, because they're scam signals. Names can't be reliably detected, so free text is still treated as
  personal information.
- Server logs contain **no IP addresses and no query strings** (so no looked-up numbers).
- Reporter ids are hashed with a secret key (HMAC), so they can't be reversed by trying every IP address.
- Retention: community reports are deleted after 12 months and Insights counters after 90 days.
- Voice notes and screenshots sent to the AI model can't be masked. On Gemini's free tier, only use
  sample data; production needs a paid tier or `LLM_TRANSCRIPTION_ENABLED=false`.

### What's in the database

SQLite (`data/triguard.db`, no setup) by default. To host the backend, set `DATABASE_URL` to a PostgreSQL URL
(e.g. Supabase or Neon free tier) - the tables are created on startup and the same code runs on both
(`app/models.py`, SQLAlchemy). Moving existing SQLite data across is a one-off export/import.

| Table | Holds | Why |
|---|---|---|
| `number_reports` | Reported number, scam type, channel, optional comment, hashed device id | Truecaller-style lookups |
| `check_events` | Check type + result level only | Insights dashboard numbers |
| `businesses`, `branches` | Business name, branches, payment threshold, TriGuard number | Android app |
| `users` | Staff name, email, role, scrypt password hash, authenticator secret | Sign-in |
| `auth_sessions`, `login_challenges`, `devices` | SHA-256 hashes of tokens, device name, push token | Sign-in, remote sign-out |
| `directory_entries` | People and suppliers, verified numbers, backup contact | Call matching, Verify |
| `calls` | Screening result: risk, reasons, action, voice signal, transcript - **no audio** | Calls and alerts |
| `verify_requests`, `verify_approvals` | Who asked whom to approve what, and the answers | Guard 3 |
| `scam_reports` | Numbers businesses reported (pending review) | Shared scam list |
| `audit_events` | Security events - no IPs, tokens or full numbers | Audit log |

Retention: transcripts are cleared after 30 days, call records deleted after 180 days, audit events after a year.
- TriGuard does **not** read WhatsApp, SMS or calls automatically. Users choose what to check:
  record/upload, paste, or **share into TriGuard** from any app (PWA Web Share Target).

## Quick start

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements.txt
copy .env.example .env   # add a free GEMINI_API_KEY from https://aistudio.google.com/apikey
uvicorn app.main:app --reload --port 8000
```

Open http://localhost:8000/docs for interactive API docs.

### Connecting the React PWA (TriGuard-AI-Frontend)

In the frontend, create `.env`:

```
VITE_USE_MOCK=false
VITE_API_URL=http://localhost:8000
```

then `npm run dev`. All calls go through `src/services/api.js`, which maps backend results to the
`{ verdict, score, reasons, reportCount }` shape the pages use (`low` counts as safe, `medium` as suspicious,
`high`/`critical` as scam) and also passes through `headline`, `summary` and `advice`.

CORS allows `localhost:5173` (dev), `4173` (preview) and `3000`, plus - in development - any port on this PC
or the local Wi-Fi. **Testing on a phone:** run the backend with `--host 0.0.0.0`, find the PC's IP
(`ipconfig`), and set `VITE_API_URL=http://<PC-IP>:8000` and `npm run dev -- --host`. Note that browsers only
allow the microphone on `https` or `localhost`, so live recording on a phone needs the deployed (https) site;
uploading a voice note works either way.

### Android app (business call protection)

The Android app (Kotlin, built in Google AI Studio) uses the endpoints without the `/api/v1` prefix: `/auth/*`,
`/me`, `/devices`, `/dashboard`, `/calls`, `/request-check`, `/verify/*`, `/directory`, `/scam-reports`, `/audit`.
The app never talks to the database directly - it calls these endpoints, and the backend reads and writes the
database.

1. Create the business and the owner's account (asks for a password, then prints the authenticator setup key):

   ```powershell
   python -m app.cli create-owner --business "SuperSave" --branch "Cape Town Main" --name "Dev Naidoo" --email owner@example.co.za --sample-data
   python -m app.cli add-user --email thabo@example.co.za --name "Thabo Molefe" --role staff --branch "Cape Town Main"
   ```

   `--sample-data` adds fictional suppliers and four screened calls so every screen has something to show.
   Roles: `owner`, `manager`, `finance`, `staff`. `reset-second-step --email ...` replaces a lost authenticator.
2. Run the server so phones can reach it: `uvicorn app.main:app --reload --host 0.0.0.0 --port 8000`
3. In the app, set `BASE_URL` (in `app/build.gradle.kts`) - it must end with `/`:
   - Android emulator: `http://10.0.2.2:8000/`
   - Phone on the same Wi-Fi: `http://<PC-IP>:8000/` (find the IP with `ipconfig`)
   - Real users: an `https://` address (hosted backend, or a tunnel such as ngrok while testing)

   Plain `http` needs a debug-only network security config in the app; remove it before release.

Sign-in: `POST /auth/login` → `mfa_token` → `POST /auth/mfa/totp` with the 6-digit code → `access_token` (15 min)
and `refresh_token` (30 days, single use). Send `Authorization: Bearer <access_token>`; on 401, call
`/auth/refresh`, and if that also fails, return to sign-in. Five wrong attempts lock sign-in for 15 minutes (429).

Not built yet: passkeys, password-reset emails, voiceprints, consents, privacy export/delete, the supplier
bank-change workflow, push notifications / `WS /events`, and the screening service that writes calls
(`app/services/calls.py: record_screened_call`).

### Outlook add-in ("Check with TriGuard" button)

`outlook-addin/` holds a read-mode Outlook add-in that sends the open email (headers with SPF/DKIM/DMARC results,
text and attachment names) to `/api/v1/email/analyze` and shows the verdict. The backend serves it at `/addin/`.
Outlook only loads add-ins over https:

```powershell
npx office-addin-dev-certs install    # once: creates and trusts a localhost certificate
$env:VOICE_MODEL_ENABLED="false"; $env:TRANSCRIPTION_ENABLED="false"   # email checks don't need the voice models
uvicorn app.main:app --port 3000 --ssl-keyfile "$HOME\.office-addin-dev-certs\localhost.key" --ssl-certfile "$HOME\.office-addin-dev-certs\localhost.crt"
```

Then in Outlook on the web (or new Outlook), open https://aka.ms/olksideload > **My add-ins** > **Add a custom
add-in** > **Add from file** and pick `outlook-addin/manifest.xml`. Open an email and click **Check with TriGuard**
(under the **Apps** button or the "..." menu). For an organisation, IT deploys the same manifest, with the hosted
https address in place of `https://localhost:3000`, from the Microsoft 365 admin centre.

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

Without an AI key everything still works using the offline rule engine (screenshot reading
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
  database.py           Database connection (SQLite or PostgreSQL)
  models.py             All tables
  db.py                 Community number reports, check counters, data clean-up
  mobile_schemas.py     Request/response models for the Android app
  cli.py                Create businesses and staff accounts
  routers/              voice, messages (+ email, screenshot, links), numbers,
                        auth + devices, business (dashboard, calls, directory, ...), verify
  services/
    audio.py            Decode webm/opus/m4a/mp3/wav -> 16 kHz mono (PyAV, no ffmpeg needed)
    voice_detector.py   Deepfake model, Whisper, acoustic features
    voice_analysis.py   Voice pipeline -> one verdict
    scam_rules.py       South African scam pattern rules + entity extraction
    llm.py              AI analysis via Gemini or Claude (structured output, multilingual, vision, audio)
    message_analysis.py Rules + links + AI -> one verdict
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
