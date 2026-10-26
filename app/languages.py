"""The 11 official languages of South Africa and which speech engine can transcribe each one."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Language:
    code: str
    name: str  # English name, used in prompts
    native_name: str  # shown in the PWA language picker
    whisper: str | None = None  # Whisper language name, if Whisper supports it well
    mms: str | None = None  # Meta MMS adapter code, if available


LANGUAGES: dict[str, Language] = {
    lang.code: lang
    for lang in (
        Language("en", "English", "English", whisper="english", mms="eng"),
        Language("af", "Afrikaans", "Afrikaans", whisper="afrikaans", mms="afr"),
        Language("zu", "isiZulu", "isiZulu", mms="zul"),
        Language("xh", "isiXhosa", "isiXhosa", mms="xho"),
        Language("nso", "Sepedi", "Sepedi", mms="nso"),
        Language("ts", "Xitsonga", "Xitsonga", mms="tso"),
        Language("st", "Sesotho", "Sesotho"),
        Language("tn", "Setswana", "Setswana"),
        Language("ss", "siSwati", "siSwati"),
        Language("ve", "Tshivenda", "Tshivenḓa"),
        Language("nr", "isiNdebele", "isiNdebele"),
    )
}

AUTO = "auto"


def normalise_language(code: str | None, default: str = "en") -> str:
    """Map user input like 'ZU', 'zu-ZA' or 'auto' to one of our codes."""
    if not code:
        return default
    code = code.strip().lower().replace("_", "-").split("-")[0]
    if code == AUTO:
        return AUTO
    return code if code in LANGUAGES else default


def language_name(code: str) -> str:
    return LANGUAGES[code].name if code in LANGUAGES else "English"
