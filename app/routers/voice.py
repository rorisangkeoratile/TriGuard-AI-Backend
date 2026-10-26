from typing import Literal

from fastapi import APIRouter, File, Form, HTTPException, UploadFile, status

from app.routers.uploads import read_upload
from app.schemas import VoiceAnalysisResponse
from app.services.audio import AudioDecodeError
from app.services.voice_analysis import CallContext, analyse_voice

router = APIRouter(prefix="/api/v1/voice", tags=["voice"])


@router.post("/analyze", response_model=VoiceAnalysisResponse)
async def analyze_voice(
    file: UploadFile = File(..., description="Recording or voice note: webm, ogg/opus, m4a, mp3 or wav."),
    language: str = Form("en", description="App language for the result (en, af, zu, xh, nso, ts, st, tn, ss, ve, nr)."),
    audio_language: str | None = Form(None, description="Language spoken in the recording; defaults to `language`."),
    unknown_number: bool = Form(False),
    asked_for_money: bool = Form(False),
    urgent_pressure: bool = Form(False),
    asked_for_secrecy: bool = Form(False),
    asked_for_otp_or_banking: bool = Form(False),
    claims_to_be: Literal["family", "bank", "employer", "government", "police", "other"] | None = Form(None),
) -> VoiceAnalysisResponse:
    """Check a voice recording for signs of AI voice cloning, plus scam tactics in what was said.

    The audio is analysed in memory and never stored.
    """
    data = await read_upload(file, allowed_prefixes=("audio/", "video/webm", "video/mp4", "video/ogg"))
    context = CallContext(
        unknown_number=unknown_number,
        asked_for_money=asked_for_money,
        urgent_pressure=urgent_pressure,
        asked_for_secrecy=asked_for_secrecy,
        asked_for_otp_or_banking=asked_for_otp_or_banking,
        claims_to_be=claims_to_be,
    )
    try:
        return await analyse_voice(data, context=context, language=language, audio_language=audio_language)
    except AudioDecodeError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
