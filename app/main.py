import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import db
from app.config import get_settings
from app.routers import messages, numbers, voice
from app.services import llm, voice_detector

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()
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
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(voice.router)
app.include_router(messages.router)
app.include_router(numbers.router)


@app.get("/health", tags=["system"])
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/v1/capabilities", tags=["system"])
def capabilities() -> dict:
    """Tells the PWA which features are live so it can hide or label anything unavailable."""
    models = voice_detector.status()
    return {
        "voice_analysis": {
            "available": True,
            "ai_model_ready": models["voice_model"] is not None,
            "models_loading": not models["loaded"],
            "transcription_ready": models["transcription_model"] is not None,
            "max_seconds": settings.max_audio_seconds,
            "errors": models["errors"],
        },
        "message_analysis": {"available": True, "ai_explanations": llm.llm_available()},
        "screenshot_analysis": {"available": llm.llm_available()},
        "email_analysis": {"available": True},
        "link_check": {"available": True, "reputation_lookup": bool(settings.google_safe_browsing_api_key)},
        "number_lookup": {"available": True},
        "languages": list(llm.LANGUAGE_NAMES),
        "coming_soon": ["face_video_deepfake", "live_call_protection"],
    }
