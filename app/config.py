from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All settings can be overridden with environment variables or a .env file."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "TriGuard AI"
    environment: str = "development"
    # Comma-separated list of origins allowed to call the API (the React PWA). 5173 = `npm run dev`,
    # 4173 = `npm run preview`. Add the deployed frontend URL here.
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://localhost:3000"
    # Also allow any port on this computer and on the local Wi-Fi, so the team can test the PWA on their phones
    # during development. Set CORS_ORIGIN_REGEX= (empty) in production.
    cors_origin_regex: str = r"https?://(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+)(:\d+)?"

    # SQLite file for community number reports (Truecaller-style lookups).
    database_path: Path = Path("data/triguard.db")
    # Secret for hashing reporter ids. If empty, one is generated and kept in data/.reporter_key.
    reporter_hash_secret: str | None = None
    seed_demo_data: bool = True

    # Voice deepfake detection (Hugging Face audio-classification model).
    voice_model_enabled: bool = True
    voice_model_id: str = "mo-thecreator/Deepfake-audio-detection"
    # Transcribe voice notes so the words can also be checked for scam tactics.
    # Whisper covers English + Afrikaans. Meta MMS (3.9 GB, opt-in) adds isiZulu, isiXhosa, Sepedi, Xitsonga.
    transcription_enabled: bool = True
    transcription_model_id: str = "openai/whisper-base"
    mms_enabled: bool = False
    mms_model_id: str = "facebook/mms-1b-all"
    max_audio_seconds: int = 60
    max_upload_mb: int = 15

    # An AI model powers the 11 official languages, plain-language explanations and screenshot reading.
    # Everything still works without one (offline rules, English results).
    #   gemini    - Google Gemini, has a free tier (GEMINI_API_KEY from https://aistudio.google.com/apikey)
    #   anthropic - Claude, paid (ANTHROPIC_API_KEY)
    #   auto      - whichever key is set, preferring Gemini
    llm_enabled: bool = True
    llm_provider: str = "auto"
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-3.8-flash"
    # Used when the main model is overloaded or slow (the free tier gets "high demand" errors at peak times).
    gemini_fallback_model: str = "gemini-3.5-flash-lite"
    gemini_timeout_seconds: float = 20
    anthropic_api_key: str | None = None
    llm_model: str = "claude-opus-5-5"
    llm_effort: str = "low"
    # Let the AI model transcribe voice notes in languages the local speech models don't cover (experimental).
    llm_transcription_enabled: bool = True

    # Optional: Google Safe Browsing v4 key for link reputation checks.
    google_safe_browsing_api_key: str | None = None

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
