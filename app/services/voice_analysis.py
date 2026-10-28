"""Voice check pipeline: decode -> acoustic features -> deepfake model -> transcript scam check -> one verdict."""

import asyncio
from dataclasses import dataclass

from app.config import get_settings
from app.languages import language_name, normalise_language
from app.schemas import Indicator, RiskLevel, VoiceAnalysisResponse, VoiceModelResult
from app.services import llm, risk, voice_detector
from app.services.audio import decode_audio, to_wav_bytes
from app.services.localize import localize
from app.services.message_analysis import analyse_message


@dataclass
class CallContext:
    """Quick yes/no answers from the user. Deepfake detectors are imperfect, but scam *behaviour* is reliable."""

    unknown_number: bool = False
    asked_for_money: bool = False
    urgent_pressure: bool = False
    asked_for_secrecy: bool = False
    asked_for_otp_or_banking: bool = False
    # Payment checks for finance staff. They describe the payment request, not a person, so nothing is stored.
    new_bank_details: bool = False
    skip_approval: bool = False
    claims_to_be: str | None = None  # family, bank, employer, government, police, other


CONTEXT_RULES = (
    ("new_bank_details", "Asked you to pay into new or changed bank details",
     "Changing a supplier's bank account by call or voice note is the classic payment fraud. "
     "Confirm the account on a number you already have before paying.", 0.6),
    ("skip_approval", "Asked you to skip the normal approval process",
     "A real executive can wait for the usual sign-off. 'Just this once, skip the process' is a fraud signal.", 0.5),
    ("asked_for_otp_or_banking", "Asked for an OTP, PIN or banking details",
     "No genuine caller - not even your bank - needs your OTP or PIN.", 0.7),
    ("asked_for_money", "Asked you to send money",
     "Voice-clone scams almost always end with an urgent request for money.", 0.4),
    ("asked_for_secrecy", "Asked you to keep it secret",
     "Scammers tell you not to check with anyone else so you can't discover the trick.", 0.4),
    ("urgent_pressure", "Pressured you to act fast",
     "Urgency stops you from verifying. A real person can wait while you call them back.", 0.25),
    ("unknown_number", "Came from a new or unknown number",
     "'I'm using a friend's phone' is a common excuse in impersonation scams.", 0.15),
)


def _context_indicators(ctx: CallContext) -> list[Indicator]:
    indicators = [
        Indicator(code=f"context_{attr}", title=title, detail=detail, weight=weight, source="rules")
        for attr, title, detail, weight in CONTEXT_RULES if getattr(ctx, attr)
    ]
    if ctx.claims_to_be and indicators:
        who = {"family": "a family member", "bank": "your bank", "employer": "your boss or employer",
               "government": "a government office", "police": "the police"}.get(ctx.claims_to_be, "someone you trust")
        indicators.append(Indicator(
            code="context_impersonation", title=f"Claims to be {who}",
            detail=f"Scammers clone the voices of people you trust. Call {who} back on a number you already have.",
            weight=0.15, source="rules",
        ))
    return indicators


def _acoustic_indicators(features: dict[str, float]) -> list[Indicator]:
    indicators = []
    if features["speech_seconds"] >= 6 and 0 < features["pitch_variation"] < 0.07:
        indicators.append(Indicator(
            code="flat_intonation", title="Unusually flat, even tone",
            detail="The voice's pitch changes very little, which is common in AI-generated speech.",
            weight=0.15, source="acoustic",
        ))
    if features["speech_seconds"] >= 10 and features["pauses_per_minute"] < 3:
        indicators.append(Indicator(
            code="no_breathing_pauses", title="Few natural pauses",
            detail="Real people pause to breathe and think. This audio has very few natural breaks.",
            weight=0.1, source="acoustic",
        ))
    return indicators


async def analyse_voice(
    data: bytes, *, context: CallContext, language: str = "en", audio_language: str | None = None
) -> VoiceAnalysisResponse:
    """`language` is the user's app language (for the result); `audio_language` is what's spoken in the
    recording, defaulting to the app language."""
    settings = get_settings()
    language = normalise_language(language)
    audio_language = normalise_language(audio_language, default=language)

    audio = await asyncio.to_thread(decode_audio, data, settings.max_audio_seconds)
    features, speech_mask = await asyncio.to_thread(voice_detector.acoustic_features, audio)

    async def words_check():
        """Transcribe, then check the words for scam tactics. Runs alongside the voice-clone model."""
        if features["speech_seconds"] < 1:
            return None, None, None, None
        text = eng = english = None
        if audio_language != "en" and llm.can_transcribe_audio():
            # Local languages: the AI model transcribes better than the small local models (Whisper base is weak
            # on Afrikaans, and isiZulu etc. have none), and gives an English translation in the same call.
            text, english = await llm.transcribe_with_ai(to_wav_bytes(audio), audio_language)
            eng = "ai_experimental" if text else None
        if text is None:
            text, eng = await asyncio.to_thread(voice_detector.transcribe, audio, audio_language)
        verdict = await analyse_message(text, channel="voice_note", language=language) if text else None
        return text, eng, english, verdict

    (probability, segments, model_error), (transcript, engine, transcript_english, transcript_risk) = await asyncio.gather(
        asyncio.to_thread(voice_detector.synthetic_probability, audio, speech_mask),
        words_check(),
    )

    indicators: list[Indicator] = []
    notes: list[str] = []

    if probability is not None:
        if probability >= 0.3:
            indicators.append(Indicator(
                code="ai_voice_signature",
                title="AI voice patterns detected" if probability >= 0.6 else "Some AI voice patterns detected",
                detail=f"Our voice model found patterns typical of cloned or synthetic speech "
                       f"({round(probability * 100)}% likelihood).",
                weight=probability, source="ai_model",
            ))
    indicators += _acoustic_indicators(features)

    low_quality = features["speech_seconds"] < voice_detector.MIN_SPEECH_SECONDS or features["signal_to_noise_db"] < 10
    if features["speech_seconds"] < 3:
        notes.append("The recording has very little speech, so the result is less reliable. Try 5-15 seconds.")
    elif low_quality:
        notes.append("The recording is noisy, so the result is less reliable.")

    if transcript is None and features["speech_seconds"] >= 1 and voice_detector.transcription_engine(audio_language) is None \
            and not llm.can_transcribe_audio():
        notes.append(
            f"We can't turn {language_name(audio_language)} speech into text yet, so we couldn't check the words. "
            "Answer the quick questions about the call to get a better result."
        )

    if transcript_risk and transcript_risk.risk_score >= 40:
        indicators.append(Indicator(
            code="scam_words_in_audio", title="What was said sounds like a scam",
            detail=transcript_risk.summary, weight=transcript_risk.risk_score / 100 * 0.8, source="llm"
            if transcript_risk.ai_used else "rules",
        ))

    indicators += _context_indicators(context)
    score = risk.score_from_indicators(indicators)
    level = risk.score_to_level(score)

    if probability is None:
        notes.insert(0, "The AI voice model isn't available right now, so this result is based on other signals only.")

    if probability is not None and probability >= 0.6:
        summary = "This voice has strong signs of being generated or cloned by AI."
    elif probability is not None and probability >= 0.3:
        summary = "This voice has some signs of AI generation, but it isn't conclusive."
    elif probability is not None:
        summary = "The voice itself sounds natural."
    else:
        summary = "We couldn't run the voice-clone check."
    if transcript_risk and transcript_risk.risk_score >= 40:
        summary += " What the caller said also matches common scam tactics."
    elif any(i.code.startswith("context_") for i in indicators) and level in (RiskLevel.high, RiskLevel.critical):
        summary += " Even if the voice sounds real, the way they're asking is a classic scam pattern."
    if notes:
        summary += " " + " ".join(notes)

    indicators.sort(key=lambda i: i.weight, reverse=True)
    result = VoiceAnalysisResponse(
        risk_level=level,
        risk_score=score,
        headline=risk.headline("voice" if probability is not None and probability >= 0.3 else "call", level),
        summary=summary,
        indicators=indicators,
        advice=risk.build_advice("voice", level),
        duration_seconds=features["duration_seconds"],
        model=VoiceModelResult(
            available=probability is not None,
            model_id=settings.voice_model_id if probability is not None else None,
            synthetic_probability=round(probability, 4) if probability is not None else None,
            segments_analysed=segments,
            note=model_error,
        ),
        acoustic_features=features,
        audio_language=audio_language,
        transcript=transcript,
        transcript_engine=engine,
        transcript_english=transcript_english,
        transcript_risk=transcript_risk,
    )
    # The transcript check is already in the user's language.
    return await localize(result, language, already_translated={transcript_risk.summary} if transcript_risk else set())
