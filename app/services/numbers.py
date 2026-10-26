"""Truecaller-style number reputation built from TriGuard community reports."""

import math
from collections import Counter
from datetime import datetime

import phonenumbers
from phonenumbers import PhoneNumberType, carrier, geocoder

from app import db
from app.schemas import CategoryCount, Indicator, NumberLookupResponse, NumberReportCategory
from app.services import risk

LINE_TYPES = {
    PhoneNumberType.MOBILE: "mobile",
    PhoneNumberType.FIXED_LINE: "landline",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "landline_or_mobile",
    PhoneNumberType.VOIP: "voip",
    PhoneNumberType.TOLL_FREE: "toll_free",
    PhoneNumberType.PREMIUM_RATE: "premium_rate",
    PhoneNumberType.SHARED_COST: "shared_cost",
}

CATEGORY_LABELS = {
    "impersonation_family": "pretending to be family",
    "impersonation_bank": "pretending to be a bank",
    "impersonation_government": "pretending to be government (SARS/SASSA)",
    "impersonation_employer": "pretending to be an employer",
    "ai_voice_clone": "using an AI-cloned voice",
    "investment_scam": "investment/crypto scams",
    "job_scam": "fake jobs",
    "delivery_scam": "fake delivery fees",
    "sim_swap_otp": "OTP / SIM-swap fraud",
    "romance_scam": "romance scams",
    "spam_marketing": "spam or sales calls",
    "other": "other scams",
}


class InvalidNumberError(ValueError):
    pass


def normalise(number: str, default_region: str = "ZA") -> tuple[str, phonenumbers.PhoneNumber]:
    try:
        parsed = phonenumbers.parse(number, default_region)
    except phonenumbers.NumberParseException as exc:
        raise InvalidNumberError("That doesn't look like a phone number.") from exc
    if not phonenumbers.is_possible_number(parsed):
        raise InvalidNumberError("That doesn't look like a complete phone number.")
    return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164), parsed


def lookup(number: str) -> NumberLookupResponse:
    e164, parsed = normalise(number)
    valid = phonenumbers.is_valid_number(parsed)
    rows = db.get_reports(e164)

    counts = Counter(r["category"] for r in rows)
    spam_only = counts and set(counts) == {"spam_marketing"}
    total = len(rows)

    indicators: list[Indicator] = []
    if total:
        # Diminishing returns: 1 report = ~0.22, 3 = ~0.53, 6 = ~0.78, 10+ = ~0.92.
        weight = 1 - math.exp(-total / 4)
        if spam_only:
            weight *= 0.4
        top_cat, _ = counts.most_common(1)[0]
        indicators.append(Indicator(
            code="community_reports",
            title=f"Reported {total} time{'s' if total != 1 else ''} by TriGuard users",
            detail=f"Most reports are for {CATEGORY_LABELS.get(top_cat, top_cat)}.",
            weight=round(weight, 3),
            source="reputation",
        ))
        if counts.get("ai_voice_clone"):
            indicators.append(Indicator(
                code="voice_clone_reports", title="Linked to AI voice-clone calls",
                detail="People reported hearing a cloned voice of someone they know from this number.",
                weight=0.3, source="reputation",
            ))

    line_type = LINE_TYPES.get(phonenumbers.number_type(parsed))
    if line_type == "voip" and total:
        indicators.append(Indicator(
            code="voip_number", title="Internet (VoIP) number",
            detail="Internet numbers are cheap to create and are often used by scammers.", weight=0.1,
            source="reputation",
        ))
    if not valid:
        indicators.append(Indicator(
            code="invalid_number", title="Number format looks unusual",
            detail="This doesn't match a normal number for its country - it may be spoofed.", weight=0.2,
            source="reputation",
        ))

    score = risk.score_from_indicators(indicators)
    level = risk.score_to_level(score)
    if total:
        summary = f"{total} TriGuard user{'s have' if total != 1 else ' has'} reported this number."
    else:
        summary = ("Nobody has reported this number yet. That doesn't guarantee it's safe - "
                   "scammers change numbers often.")

    return NumberLookupResponse(
        number=e164,
        valid=valid,
        region=geocoder.description_for_number(parsed, "en") or None,
        # Network shown is the original allocation; ported numbers may now be on another network.
        carrier=carrier.name_for_number(parsed, "en") or None,
        line_type=line_type,
        total_reports=total,
        categories=[CategoryCount(category=NumberReportCategory(c), count=n) for c, n in counts.most_common()],
        last_reported_at=datetime.fromisoformat(rows[0]["created_at"]) if rows else None,
        recent_comments=[r["comment"] for r in rows if r["comment"]][:5],
        risk_level=level,
        risk_score=score,
        headline=risk.headline("number", level),
        summary=summary,
        indicators=indicators,
        advice=risk.build_advice("number", level),
    )
