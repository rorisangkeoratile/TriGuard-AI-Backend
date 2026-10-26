import io
import json
import math
import struct
import wave

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client(tmp_path_factory, monkeypatch_module):
    monkeypatch_module.setenv("DATABASE_PATH", str(tmp_path_factory.mktemp("db") / "test.db"))
    monkeypatch_module.setenv("VOICE_MODEL_ENABLED", "false")
    monkeypatch_module.setenv("TRANSCRIPTION_ENABLED", "false")
    monkeypatch_module.setenv("LLM_ENABLED", "false")
    monkeypatch_module.setenv("MMS_ENABLED", "false")
    # Tests must not depend on the developer's real .env.
    for key in ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch_module.setenv(key, "")
    from app.config import get_settings

    get_settings.cache_clear()
    from app.main import app

    with TestClient(app) as c:
        yield c
    get_settings.cache_clear()


@pytest.fixture(scope="module")
def monkeypatch_module():
    mp = pytest.MonkeyPatch()
    yield mp
    mp.undo()


def make_wav(seconds: float = 3.0, freq: float = 180.0) -> bytes:
    sr = 16_000
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(sr)
        frames = b"".join(
            struct.pack("<h", int(8000 * math.sin(2 * math.pi * (freq + 20 * math.sin(i / 800)) * i / sr)
                                  * (1 if (i // 8000) % 3 else 0.01)))
            for i in range(int(seconds * sr))
        )
        w.writeframes(frames)
    return buf.getvalue()


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_capabilities_lists_all_11_languages(client):
    caps = client.get("/api/v1/capabilities").json()
    assert caps["voice_analysis"]["available"] is True
    codes = {lang["code"] for lang in caps["languages"]}
    assert codes == {"en", "af", "zu", "xh", "nso", "ts", "st", "tn", "ss", "ve", "nr"}
    assert all(lang["voice_clone_check"] for lang in caps["languages"])


@pytest.mark.parametrize("text", [
    "Ma, dis my nuwe nommer. My foon is gesteel. Stuur asseblief dringend geld, R2000",  # af
    "Mama, le yinombolo yami entsha. Ngicela ungithumelele imali ngokushesha",  # zu
    "Mama, yinombolo yam entsha le. Ndithumelele imali ngokukhawuleza",  # xh
])
def test_offline_rules_catch_scams_in_other_languages(client, text):
    body = client.post("/api/v1/messages/analyze", json={"text": text}).json()
    assert body["risk_level"] in ("medium", "high", "critical"), body
    assert body["scam_type"] == "family_impersonation"


def test_plain_family_greeting_is_not_flagged(client):
    body = client.post("/api/v1/messages/analyze", json={"text": "Hi Mom, I'll be home late tonight"}).json()
    assert body["risk_level"] == "safe"


def test_results_are_translated_with_claude(client, monkeypatch):
    """Fake Claude so we can check the multilingual flow without an API key or network."""
    from app.services import llm

    calls = []

    async def fake_call(content, model, system, max_tokens):
        calls.append(model.__name__)
        if model is llm.LLMVerdict:
            return llm.LLMVerdict(
                detected_language="zu", risk_score=90, scam_type="family_impersonation",
                headline="ZU headline", summary="ZU summary",
                red_flags=[llm.RedFlag(title="ZU flag", detail="ZU detail", severity="high")],
                advice=["ZU advice"], extracted_text="",
            )
        strings = json.loads(content[0]["text"].split(":\n", 1)[1])
        return llm.Translation(translations=[f"[zu] {s}" for s in strings])

    monkeypatch.setattr(llm, "llm_available", lambda: True)
    monkeypatch.setattr(llm, "_structured_call", fake_call)
    monkeypatch.setattr("app.services.localize.llm_available", lambda: True)
    llm._translation_cache.clear()

    body = client.post("/api/v1/messages/analyze", json={
        "text": "Mama, le yinombolo yami entsha. Ngicela ungithumelele imali ngokushesha", "language": "auto",
    }).json()
    assert body["detected_language"] == "zu"
    assert body["language"] == "zu"
    assert body["headline"] == "ZU headline"  # written by Claude, not re-translated
    rule_titles = [i["title"] for i in body["indicators"] if i["source"] == "rules"]
    assert rule_titles and all(t.startswith("[zu] ") for t in rule_titles)
    assert body["disclaimer"].startswith("[zu] ")

    number = client.get("/api/v1/numbers/lookup", params={"number": "0710000001", "language": "zu"}).json()
    assert number["language"] == "zu" and number["headline"].startswith("[zu] ")
    llm._translation_cache.clear()


def test_family_scam_message_is_high_risk(client):
    r = client.post("/api/v1/messages/analyze", json={
        "text": "Hi Mom, this is my new number, I lost my phone. Please send R1500 via eWallet urgently, "
                "don't tell dad",
        "channel": "whatsapp",
    })
    body = r.json()
    assert r.status_code == 200
    assert body["risk_level"] in ("high", "critical")
    assert body["scam_type"] == "family_impersonation"
    assert "R1500" in body["entities"]["amounts"][0]


def test_bank_otp_scam(client):
    r = client.post("/api/v1/messages/analyze", json={
        "text": "FNB: Your account has been suspended. Share the OTP we sent you to reactivate immediately.",
        "channel": "sms",
    })
    assert r.json()["risk_level"] in ("high", "critical")


def test_normal_message_is_safe(client):
    r = client.post("/api/v1/messages/analyze", json={"text": "See you at church on Sunday, bring the chairs"})
    assert r.json()["risk_level"] == "safe"


def test_lookalike_link(client):
    r = client.post("/api/v1/links/check", json={"url": "http://capitec-secure-login.xyz/verify"}).json()
    assert r["risk_level"] in ("high", "critical")
    assert any(i["code"] == "brand_lookalike" for i in r["indicators"])


def test_official_link_is_safe(client):
    r = client.post("/api/v1/links/check", json={"url": "https://www.fnb.co.za/"}).json()
    assert r["risk_level"] == "safe"


def test_email_spoofing(client):
    raw = (
        "From: \"Standard Bank\" <alerts.standardbank@gmail.com>\r\n"
        "Reply-To: help@stdbank-support.top\r\n"
        "Authentication-Results: mx.google.com; dmarc=fail; spf=softfail\r\n"
        "Subject: Urgent: verify your account\r\n"
        "Content-Type: text/html\r\n\r\n"
        "<p>Your profile is locked. <a href='http://stdbank-verify.top/login'>www.standardbank.co.za</a></p>"
    )
    r = client.post("/api/v1/email/analyze", data={"raw": raw}).json()
    codes = {i["code"] for i in r["indicators"]}
    assert {"dmarc_fail", "reply_to_mismatch", "brand_from_freemail", "link_text_mismatch"} <= codes
    assert r["risk_level"] == "critical"


def test_number_lookup_and_report(client):
    seeded = client.get("/api/v1/numbers/lookup", params={"number": "071 000 0001"}).json()
    assert seeded["number"] == "+27710000001"
    assert seeded["total_reports"] >= 6
    assert seeded["risk_level"] in ("high", "critical")

    new = "0839990001"
    assert client.get("/api/v1/numbers/lookup", params={"number": new}).json()["total_reports"] == 0
    body = {"number": new, "category": "impersonation_bank", "reporter_id": "device-1"}
    assert client.post("/api/v1/numbers/report", json=body).json()["accepted"] is True
    assert client.post("/api/v1/numbers/report", json=body).json()["accepted"] is False
    assert client.get("/api/v1/numbers/lookup", params={"number": new}).json()["total_reports"] == 1

    trending = client.get("/api/v1/numbers/trending").json()
    assert trending[0]["number"] == "+27710000001"


def test_invalid_number(client):
    assert client.get("/api/v1/numbers/lookup", params={"number": "abc"}).status_code == 422


def test_voice_without_model_uses_context(client):
    r = client.post(
        "/api/v1/voice/analyze",
        files={"file": ("note.wav", make_wav(), "audio/wav")},
        data={"asked_for_money": "true", "asked_for_secrecy": "true", "urgent_pressure": "true",
              "claims_to_be": "family"},
    )
    body = r.json()
    assert r.status_code == 200, body
    assert body["model"]["available"] is False
    assert body["duration_seconds"] == pytest.approx(3.0, abs=0.1)
    assert body["risk_level"] in ("medium", "high", "critical")


def test_voice_rejects_garbage(client):
    r = client.post("/api/v1/voice/analyze", files={"file": ("x.wav", b"not audio at all", "audio/wav")})
    assert r.status_code == 422
