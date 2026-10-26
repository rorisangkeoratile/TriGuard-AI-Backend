"""Turns raw indicator weights into a 0-100 score, a risk level and plain-language advice."""

from app.schemas import Indicator, RiskLevel


def combine_weights(weights: list[float]) -> float:
    """Noisy-OR: several independent weak signals add up, but never exceed 1."""
    remaining = 1.0
    for w in weights:
        remaining *= 1.0 - max(0.0, min(1.0, w))
    return 1.0 - remaining


def score_to_level(score: int) -> RiskLevel:
    if score >= 85:
        return RiskLevel.critical
    if score >= 65:
        return RiskLevel.high
    if score >= 40:
        return RiskLevel.medium
    if score >= 15:
        return RiskLevel.low
    return RiskLevel.safe


def score_from_indicators(indicators: list[Indicator]) -> int:
    return round(combine_weights([i.weight for i in indicators]) * 100)


HEADLINES = {
    "voice": {
        RiskLevel.safe: "No signs of a cloned voice",
        RiskLevel.low: "Probably a real voice",
        RiskLevel.medium: "Some signs this voice may be AI-generated",
        RiskLevel.high: "This voice shows strong signs of AI cloning",
        RiskLevel.critical: "Very likely an AI-generated voice",
    },
    # Voice checks where the risk comes from what the caller did/said rather than the voice itself.
    "call": {
        RiskLevel.safe: "No warning signs found",
        RiskLevel.low: "A few things to double-check",
        RiskLevel.medium: "Be careful - this call has warning signs",
        RiskLevel.high: "This call follows a scam pattern",
        RiskLevel.critical: "This call is almost certainly a scam",
    },
    "message": {
        RiskLevel.safe: "No scam signs found",
        RiskLevel.low: "Looks mostly safe",
        RiskLevel.medium: "Be careful - this message has warning signs",
        RiskLevel.high: "This looks like a scam",
        RiskLevel.critical: "Almost certainly a scam",
    },
    "link": {
        RiskLevel.safe: "No problems found with this link",
        RiskLevel.low: "Link looks mostly safe",
        RiskLevel.medium: "This link looks suspicious",
        RiskLevel.high: "Dangerous link - do not open it",
        RiskLevel.critical: "Known dangerous link - do not open it",
    },
    "number": {
        RiskLevel.safe: "No reports for this number",
        RiskLevel.low: "A few reports for this number",
        RiskLevel.medium: "This number has been reported by the community",
        RiskLevel.high: "Many people reported this number as a scam",
        RiskLevel.critical: "Widely reported scam number",
    },
}


BASE_ADVICE = {
    "voice": [
        "Hang up and call the person back on the number you have saved for them.",
        "Ask a question only the real person would know, or agree on a family 'safe word'.",
        "Never send money, OTPs or banking details because of a voice note or call alone.",
    ],
    "message": [
        "Don't click links or reply until you've checked the message independently.",
        "Contact the bank, company or person through their official app, website or a number you already trust.",
        "Never share OTPs, PINs or passwords - real banks and SARS/SASSA will never ask for them.",
    ],
    "link": [
        "Type the official website address yourself instead of tapping the link.",
        "If you already entered banking details, call your bank's fraud line immediately.",
    ],
    "number": [
        "Don't share personal information or OTPs with this caller.",
        "If they claim to be from a bank or company, hang up and call the official number on its website or your card.",
    ],
}

ESCALATION_ADVICE = [
    "If you've lost money, contact your bank immediately, then report it to SAPS and the SABRIC/bank fraud line.",
    "Report the number in TriGuard to warn other South Africans.",
]


def build_advice(kind: str, level: RiskLevel) -> list[str]:
    advice = list(BASE_ADVICE.get(kind, BASE_ADVICE["message"]))
    if level in (RiskLevel.high, RiskLevel.critical):
        advice = ["Stop the conversation now - do not pay or share any information."] + advice + ESCALATION_ADVICE
    elif level == RiskLevel.safe:
        advice = ["Stay alert - scammers change tactics quickly."] + advice[:1]
    return advice


def headline(kind: str, level: RiskLevel) -> str:
    return HEADLINES.get(kind, HEADLINES["message"])[level]
