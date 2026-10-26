from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All settings can be overridden with environment variables or a .env file."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "TriGuard AI"
    environment: str = "development"
    # Comma-separated list of origins allowed to call the API (the React PWA).
    cors_origins: str = "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173"

    # SQLite file for community number reports (Truecaller-style lookups).
    database_path: Path = Path("data/triguard.db")
    seed_demo_data: bool = True

    # Voice deepfake detection (Hugging Face audio-classification model).
    voice_model_enabled: bool = True
    voice_model_id: str = "mo-thecreator/Deepfake-audio-detection"
    # Transcribe voice notes so the words can also be checked for scam tactics.
    transcription_enabled: bool = True
    transcription_model_id: str = "openai/whisper-base"
    max_audio_seconds: int = 60
    max_upload_mb: int = 15

    # Claude is used for plain-language scam analysis and screenshot reading.
    # Uses ANTHROPIC_API_KEY from the environment; everything still works without it (rules only).
    llm_enabled: bool = True
    llm_model: str = "claude-opus-5-5"
    llm_effort: str = "low"

    # Optional: Google Safe Browsing v4 key for link reputation checks.
    google_safe_browsing_api_key: str | None = None

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
