"""Combines the rule engine, link checks and Claude into one verdict for a message, email or screenshot."""

import asyncio

from app.schemas import Indicator, MessageAnalysisResponse, RiskLevel
from app.services import llm, risk
from app.services.links import check_link
from app.services.scam_rules import extract_entities, run_rules

SEVERITY_WEIGHT = {"low": 0.2, "medium": 0.4, "high": 0.65}


async def analyse_message(
    text: str,
    *,
    channel: str = "other",
    sender: str | None = None,
    language: str = "en",
    kind: str = "message",
    extra_indicators: list[Indicator] | None = None,
    image: tuple[bytes, str] | None = None,
) -> MessageAnalysisResponse:
    rule_indicators, scam_type = run_rules(text) if text else ([], None)
    indicators = list(extra_indicators or []) + rule_indicators

    verdict = await llm.analyse_with_claude(
        text=text or None,
        channel=channel,
        sender=sender,
        language=language,
        rule_findings=[i.title for i in indicators],
        image=image,
    )

    # Screenshots only have text once Claude has read them.
    extracted_text = verdict.extracted_text.strip() if verdict and verdict.extracted_text else None
    if image and extracted_text and not text:
        text = extracted_text
        rule_indicators, scam_type = run_rules(text)
        indicators += rule_indicators

    entities = extract_entities(text) if text else extract_entities("")
    links = list(await asyncio.gather(*(check_link(u) for u in entities.urls[:5])))
    for link in links:
        if link.risk_level in (RiskLevel.medium, RiskLevel.high, RiskLevel.critical):
            top = link.indicators[0] if link.indicators else None
            indicators.append(Indicator(
                code="dangerous_link",
                title=f"Contains a suspicious link ({link.domain})",
                detail=top.detail if top else "This link has warning signs.",
                weight=min(0.9, link.risk_score / 100),
                source="link",
            ))

    rules_score = risk.score_from_indicators(indicators)

    if verdict:
        for flag in verdict.red_flags:
            indicators.append(Indicator(
                code="ai_" + flag.severity, title=flag.title, detail=flag.detail,
                weight=SEVERITY_WEIGHT[flag.severity], source="llm",
            ))
        # Claude reads context the rules can't (and spots false alarms), so it leads,
        # but hard evidence like a blocklisted link or an OTP request keeps a floor under the score.
        hard_floor = max((i.weight for i in indicators if i.source in ("link", "reputation", "email_auth")), default=0)
        score = max(round(0.7 * verdict.risk_score + 0.3 * rules_score), round(hard_floor * 100))
        level = risk.score_to_level(score)
        headline_text, summary = verdict.headline, verdict.summary
        advice = verdict.advice + [a for a in risk.build_advice("message", level) if a not in verdict.advice][:2]
        if verdict.scam_type and verdict.scam_type != "none":
            scam_type = verdict.scam_type
        elif score < 40:
            scam_type = None
    else:
        score = rules_score
        level = risk.score_to_level(score)
        headline_text = risk.headline("message", level)
        summary = (
            f"We found {len(indicators)} warning sign{'s' if len(indicators) != 1 else ''} commonly used in scams."
            if indicators else "We didn't find common scam patterns in this message."
        )
        advice = risk.build_advice("message", level)

    indicators.sort(key=lambda i: i.weight, reverse=True)
    return MessageAnalysisResponse(
        kind=kind,
        risk_level=level,
        risk_score=score,
        headline=headline_text,
        summary=summary,
        indicators=indicators,
        advice=advice,
        scam_type=scam_type,
        entities=entities,
        links=links,
        ai_used=verdict is not None,
        extracted_text=extracted_text if image else None,
    )
