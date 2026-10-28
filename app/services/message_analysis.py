"""Combines the rule engine, link checks and the AI model into one verdict for a message, email or screenshot."""

import asyncio
import re

from app.languages import AUTO, LANGUAGES, normalise_language
from app.schemas import Indicator, MessageAnalysisResponse, RiskLevel
from app.services import llm, risk
from app.services.links import check_link
from app.services.localize import localize
from app.services.scam_rules import extract_entities, run_rules

SEVERITY_WEIGHT = {"low": 0.2, "medium": 0.4, "high": 0.65}

# What a warning is about, so the AI's red flags don't repeat what the rules already said in other words.
TOPICS = {
    "secrecy": re.compile(r"secre|confidential|between us|tell (anyone|no one|nobody)", re.I),
    "urgency": re.compile(r"urgen|immediate|pressure|rush|deadline|act fast", re.I),
    "money": re.compile(r"money|transfer|payment|\bpay\b|funds|\beft\b", re.I),
    "meeting": re.compile(r"video|meeting|teams|zoom", re.I),
    "sender": re.compile(r"sender|e-?mail (address|account)|domain|free email|outside your", re.I),
    "link": re.compile(r"(?<!call )link|url|website", re.I),
    "bank": re.compile(r"bank(ing)? details|account details|new account|changed? (bank|account)", re.I),
    "credentials": re.compile(r"\botp\b|\bpin\b|password", re.I),
    "approval": re.compile(r"approv|bypass|skip (the )?(normal|usual)|procedure", re.I),
}


def _topics(text: str) -> set[str]:
    return {name for name, rx in TOPICS.items() if rx.search(text)}


async def analyse_message(
    text: str,
    *,
    channel: str = "other",
    sender: str | None = None,
    language: str = AUTO,
    kind: str = "message",
    extra_indicators: list[Indicator] | None = None,
    image: tuple[bytes, str] | None = None,
) -> MessageAnalysisResponse:
    """`language` is the language to answer in, or "auto" to answer in the message's own language."""
    language = normalise_language(language, default=AUTO)
    rule_indicators, scam_type = run_rules(text) if text else ([], None)
    indicators = list(extra_indicators or []) + rule_indicators

    verdict = await llm.analyse_message_with_ai(
        text=text or None,
        channel=channel,
        sender=sender,
        language=language,
        rule_findings=[i.title for i in indicators],
        image=image,
    )

    # Screenshots only have text once the AI has read them.
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
        # Show each warning once: skip an AI flag when the rules (or an earlier AI flag) already cover its topic.
        covered = set().union(*(_topics(i.title) for i in indicators))
        for flag in verdict.red_flags:
            topics = _topics(flag.title)
            if topics and topics <= covered:
                continue
            covered |= topics
            indicators.append(Indicator(
                code="ai_" + flag.severity, title=flag.title, detail=flag.detail,
                weight=SEVERITY_WEIGHT[flag.severity], source="llm",
            ))
        # The AI reads context the rules can't (and spots false alarms), so it leads,
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
    detected = verdict.detected_language if verdict and verdict.detected_language in LANGUAGES else None
    target = language
    if target == AUTO:
        target = detected or "en"
    ai_wrote = set()
    if verdict:
        ai_wrote = {verdict.headline, verdict.summary, *verdict.advice,
                        *(t for f in verdict.red_flags for t in (f.title, f.detail))}

    result = MessageAnalysisResponse(
        kind=kind,
        risk_level=level,
        risk_score=score,
        headline=headline_text,
        summary=summary,
        indicators=indicators,
        advice=advice,
        scam_type=scam_type,
        detected_language=detected,
        entities=entities,
        links=links,
        ai_used=verdict is not None,
        extracted_text=extracted_text if image else None,
    )
    if verdict and target != "en":
        result.language = target  # The AI already wrote its parts in the target language
    # Link results reuse the same fixed sentences, so after the first time these come from the cache.
    await asyncio.gather(*(localize(link, target) for link in result.links))
    return await localize(result, target, already_translated=ai_wrote)
