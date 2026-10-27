"""AI voice-clone detection.

1. A wav2vec2 deepfake-audio classifier (Hugging Face) scores short speech windows.
2. Simple acoustic measurements explain the result in human terms and flag audio too poor to judge.
3. Optionally, Whisper transcribes the audio so the *words* can be checked for scam tactics too.
"""

import logging
import os
import threading
from dataclasses import dataclass, field

import numpy as np

from app.config import get_settings
from app.languages import LANGUAGES
from app.services.audio import TARGET_SR

log = logging.getLogger(__name__)

# The Xet transfer backend can stall at 0 bytes on some networks; plain HTTP downloads are reliable.
os.environ.setdefault("HF_HUB_DISABLE_XET", "1")

WINDOW_SECONDS = 4.0
MIN_SPEECH_SECONDS = 1.0


@dataclass
class _Models:
    classifier: object | None = None
    extractor: object | None = None
    fake_index: int | None = None
    asr: object | None = None
    mms_model: object | None = None
    mms_processor: object | None = None
    errors: dict[str, str] = field(default_factory=dict)
    loaded: bool = False


_models = _Models()
_lock = threading.Lock()
_mms_lock = threading.Lock()


def load_models(wait: bool = True) -> _Models:
    """Load models once (called at startup in a background thread, or lazily on first use).

    With wait=False (used by requests), returns whatever is loaded so far instead of blocking while a slow
    download finishes - e.g. the voice model can be used while Whisper is still downloading.
    """
    if not _lock.acquire(blocking=wait):
        return _models
    try:
        if _models.loaded:
            return _models
        settings = get_settings()
        try:
            import torch  # noqa: F401
            from transformers import AutoFeatureExtractor, AutoModelForAudioClassification, pipeline
        except ImportError as exc:
            _models.errors["voice"] = f"ML libraries not installed ({exc.name})"
            _models.loaded = True
            return _models

        if settings.voice_model_enabled:
            try:
                _models.extractor = AutoFeatureExtractor.from_pretrained(settings.voice_model_id)
                model = AutoModelForAudioClassification.from_pretrained(settings.voice_model_id)
                model.eval()
                labels = {int(k): v.lower() for k, v in model.config.id2label.items()}
                fake = [i for i, lbl in labels.items() if any(w in lbl for w in ("fake", "spoof", "synthetic"))]
                if not fake:
                    raise ValueError(f"can't find a 'fake' label in {labels}")
                _models.fake_index = fake[0]
                _models.classifier = model
                log.info("Loaded voice model %s (labels %s)", settings.voice_model_id, labels)
            except Exception as exc:  # model download / format problems shouldn't crash the API
                log.exception("Voice model failed to load")
                _models.errors["voice"] = str(exc)

        if settings.transcription_enabled:
            try:
                _models.asr = pipeline(
                    "automatic-speech-recognition", model=settings.transcription_model_id, device="cpu"
                )
                log.info("Loaded transcription model %s", settings.transcription_model_id)
            except Exception as exc:
                log.exception("Transcription model failed to load")
                _models.errors["transcription"] = str(exc)

        if settings.transcription_enabled and settings.mms_enabled:
            try:
                from transformers import AutoProcessor, Wav2Vec2ForCTC

                _models.mms_processor = AutoProcessor.from_pretrained(settings.mms_model_id)
                _models.mms_model = Wav2Vec2ForCTC.from_pretrained(settings.mms_model_id)
                _models.mms_model.eval()
                log.info("Loaded multilingual transcription model %s", settings.mms_model_id)
            except Exception as exc:
                log.exception("MMS model failed to load")
                _models.errors["mms"] = str(exc)

        _models.loaded = True
        return _models
    finally:
        _lock.release()


def status() -> dict:
    return {
        "loaded": _models.loaded,
        "voice_model": get_settings().voice_model_id if _models.classifier is not None else None,
        "transcription_model": get_settings().transcription_model_id if _models.asr is not None else None,
        "transcription_languages": [code for code in LANGUAGES if transcription_engine(code)],
        "errors": _models.errors,
    }


# ---------------------------------------------------------------- acoustic features

def _frames(audio: np.ndarray, size: int, hop: int) -> np.ndarray:
    if audio.size < size:
        audio = np.pad(audio, (0, size - audio.size))
    count = 1 + (audio.size - size) // hop
    idx = np.arange(size)[None, :] + hop * np.arange(count)[:, None]
    return audio[idx]


def _pitch(frame: np.ndarray) -> float | None:
    frame = frame - frame.mean()
    corr = np.correlate(frame, frame, mode="full")[frame.size - 1:]
    if corr[0] <= 0:
        return None
    lo, hi = TARGET_SR // 400, TARGET_SR // 70  # 70-400 Hz human voice range
    lag = lo + int(np.argmax(corr[lo:hi]))
    return TARGET_SR / lag if corr[lag] / corr[0] > 0.35 else None


def acoustic_features(audio: np.ndarray) -> tuple[dict[str, float], np.ndarray]:
    """Return human-readable measurements plus a boolean speech mask per 25 ms frame."""
    size, hop = int(0.025 * TARGET_SR), int(0.010 * TARGET_SR)
    frames = _frames(audio, size, hop)
    rms = np.sqrt(np.mean(frames ** 2, axis=1) + 1e-12)
    rms_db = 20 * np.log10(rms + 1e-9)
    noise_floor = np.percentile(rms_db, 10)
    speech = rms_db > max(noise_floor + 12, -50)

    spectrum = np.abs(np.fft.rfft(frames * np.hanning(size), axis=1)) + 1e-10
    flatness = np.exp(np.mean(np.log(spectrum), axis=1)) / np.mean(spectrum, axis=1)

    voiced_frames = frames[speech][:: max(1, int(speech.sum() // 300))]  # sample at most ~300 frames
    pitches = [p for p in (_pitch(f) for f in voiced_frames) if p]
    pitch_cv = float(np.std(pitches) / np.mean(pitches)) if len(pitches) > 10 else 0.0

    # Count pauses: runs of >= 150 ms of non-speech between speech.
    pauses, run = 0, 0
    for is_speech in speech:
        if is_speech:
            if run >= 15:
                pauses += 1
            run = 0
        else:
            run += 1

    speech_seconds = float(speech.sum() * hop / TARGET_SR)
    features = {
        "duration_seconds": round(audio.size / TARGET_SR, 2),
        "speech_seconds": round(speech_seconds, 2),
        "speech_ratio": round(float(speech.mean()), 3),
        "pauses_per_minute": round(pauses / max(speech_seconds / 60, 1e-6), 1) if speech_seconds > 0 else 0.0,
        "pitch_variation": round(pitch_cv, 3),
        "spectral_flatness": round(float(np.mean(flatness[speech])) if speech.any() else 0.0, 4),
        "signal_to_noise_db": round(float(np.percentile(rms_db, 90) - noise_floor), 1),
        "clipping_ratio": round(float(np.mean(np.abs(audio) > 0.99)), 4),
    }
    return features, speech


# ---------------------------------------------------------------- model inference

def _speech_windows(audio: np.ndarray, speech_mask: np.ndarray) -> list[np.ndarray]:
    win = int(WINDOW_SECONDS * TARGET_SR)
    hop_samples = int(0.010 * TARGET_SR)
    windows = []
    for start in range(0, max(1, audio.size - win // 2), win):
        chunk = audio[start:start + win]
        mask = speech_mask[start // hop_samples:(start + chunk.size) // hop_samples]
        if chunk.size >= TARGET_SR and (mask.size == 0 or mask.mean() > 0.3):
            windows.append(chunk)
    return windows[:15] or [audio[:win]]


def synthetic_probability(audio: np.ndarray, speech_mask: np.ndarray) -> tuple[float | None, int, str | None]:
    models = load_models(wait=False)
    if models.classifier is None:
        return None, 0, models.errors.get("voice", "Voice model disabled" if models.loaded else "Voice model is still loading")

    import torch

    windows = _speech_windows(audio, speech_mask)
    inputs = models.extractor(
        windows, sampling_rate=TARGET_SR, return_tensors="pt", padding=True, return_attention_mask=True
    )
    with torch.inference_mode():
        logits = models.classifier(**inputs).logits
    probs = torch.softmax(logits, dim=-1)[:, models.fake_index].numpy()
    # Blend mean and max: a clone spliced into a real recording should still raise the score.
    score = float(0.6 * probs.mean() + 0.4 * probs.max())
    return score, len(windows), None


def transcription_engine(language: str) -> str | None:
    """Which engine can transcribe `language` right now: 'whisper', 'mms' or None."""
    lang = LANGUAGES.get(language)
    if lang is None:
        return None
    if lang.whisper and _models.asr is not None:
        return "whisper"
    if lang.mms and _models.mms_model is not None:
        return "mms"
    return None


def transcribe(audio: np.ndarray, language: str) -> tuple[str | None, str | None]:
    """Transcribe speech in `language`. Returns (text, engine), or (None, None) if unsupported."""
    load_models(wait=False)
    engine = transcription_engine(language)
    try:
        if engine == "whisper":
            result = _models.asr(
                {"raw": audio, "sampling_rate": TARGET_SR},
                return_timestamps=audio.size > 30 * TARGET_SR,
                generate_kwargs={"task": "transcribe", "language": LANGUAGES[language].whisper},
            )
            text = result.get("text") or ""
        elif engine == "mms":
            import torch

            # MMS swaps a small per-language adapter into one shared model, so requests take turns.
            with _mms_lock:
                _models.mms_processor.tokenizer.set_target_lang(LANGUAGES[language].mms)
                _models.mms_model.load_adapter(LANGUAGES[language].mms)
                inputs = _models.mms_processor(audio, sampling_rate=TARGET_SR, return_tensors="pt")
                with torch.inference_mode():
                    logits = _models.mms_model(**inputs).logits
                text = _models.mms_processor.decode(logits.argmax(dim=-1)[0])
        else:
            return None, None
    except Exception:
        log.exception("Transcription failed (%s, %s)", engine, language)
        return None, None
    text = text.strip()
    return (text, engine) if text else (None, None)
