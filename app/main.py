import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app import db
from app.config import get_settings
from app.languages import LANGUAGES
from app.routers import insights, messages, numbers, voice
from app.services import llm, voice_detector
from app.services.privacy import AccessLogFilter

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logging.getLogger("uvicorn.access").addFilter(AccessLogFilter())


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()
    db.purge_old_data()
    # Load the ML models in the background so the API is available immediately.
    loader = asyncio.create_task(asyncio.to_thread(voice_detector.load_models))
    yield
    loader.cancel()


settings = get_settings()
app = FastAPI(
    title="TriGuard AI API",
    description="Trace the fake. Protect the truth. - AI voice-clone, scam message, link and number checks "
                "for everyday South Africans.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_origin_regex=settings.cors_origin_regex or None,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(voice.router)
app.include_router(messages.router)
app.include_router(numbers.router)
app.include_router(insights.router)

# Outlook add-in ("Check with TriGuard" button). Outlook only loads add-ins over https, so for this, run the
# server with --ssl-keyfile/--ssl-certfile (see README).
ADDIN_DIR = Path(__file__).resolve().parent.parent / "outlook-addin"
if ADDIN_DIR.is_dir():
    app.mount("/addin", StaticFiles(directory=ADDIN_DIR), name="outlook-addin")


@app.get("/health", tags=["system"])
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/v1/capabilities", tags=["system"])
def capabilities() -> dict:
    """Tells the PWA which features are live so it can hide or label anything unavailable."""
    models = voice_detector.status()
    llm_ready = llm.llm_available()
    return {
        "voice_analysis": {
            "available": True,
            "ai_model_ready": models["voice_model"] is not None,
            "models_loading": not models["loaded"],
            "transcription_ready": models["transcription_model"] is not None,
            "max_seconds": settings.max_audio_seconds,
            "errors": models["errors"],
        },
        "ai_provider": llm.provider(),
        "message_analysis": {"available": True, "ai_explanations": llm_ready},
        "screenshot_analysis": {"available": llm_ready},
        "email_analysis": {"available": True},
        "link_check": {"available": True, "reputation_lookup": bool(settings.google_safe_browsing_api_key)},
        "number_lookup": {"available": True},
        # What works in each official language, so the PWA can set expectations in its language picker.
        "languages": [
            {
                "code": lang.code,
                "name": lang.native_name,
                "results_in_language": llm_ready or lang.code == "en",
                "understands_messages": llm_ready or lang.code == "en",
                "voice_clone_check": True,
                "voice_transcription": "local" if lang.code in models["transcription_languages"]
                else "ai_experimental" if llm.can_transcribe_audio() else None,
            }
            for lang in LANGUAGES.values()
        ],
        "coming_soon": ["face_video_deepfake", "live_call_protection"],
    }
