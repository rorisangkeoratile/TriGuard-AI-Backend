"""Fast, offline scam-pattern detection tuned for South African scams.

Rules give an instant result and still work when the AI service is unavailable.
"""

import re
from dataclasses import dataclass

from app.schemas import ExtractedEntities, Indicator


@dataclass(frozen=True)
class Rule:
    code: str
    title: str
    detail: str
    weight: float
    patterns: tuple[str, ...]
    scam_type: str | None = None


# Brands and institutions South African scammers most often impersonate.
SA_BRANDS = (
    "fnb", "first national bank", "capitec", "absa", "standard bank", "nedbank", "tymebank", "discovery bank",
    "african bank", "investec", "sars", "sassa", "home affairs", "nsfas", "post office", "sapo", "eskom",
    "vodacom", "mtn", "telkom", "cell c", "rain", "takealot", "checkers", "shoprite", "pick n pay", "dhl",
    "the courier guy", "aramex", "pargo", "postnet", "netflix", "dstv", "multichoice", "gautrain", "e-toll",
    "sanral", "traffic fine", "saps",
)

# Key scam phrases in the other official languages, so the offline rules still catch the most common
# scams when no AI model is available. The AI handles the full meaning of messages in every language.
# TODO: have native speakers on the team review and extend these.
ML: dict[str, tuple[str, ...]] = {
    "new_number": (
        r"\b(my )?nuwe nommer\b", r"\bfoon (is )?(gesteel|verloor|stukkend)\b",  # af
        # Nguni nouns take prefixes ("le yinombolo yami entsha" = "this is my new number").
        r"\b[yl]?inombolo (yami |yam )?entsha\b",  # zu, xh
        r"\b[yl]?inombolo (yami )?lensha\b",  # ss
        r"\bnomoro (ya ka |yaka |ya )?(e ?ntjha|e ?ntšha|e ?ntsha|ye ?mpsha)\b",  # st, tn, nso
        r"\bnomboro (ya mina )?(leyintshwa|yintshwa)\b",  # ts
        r"\bnomboro (yanga )?ntswa\b",  # ve
    ),
    "send_money": (
        r"\bstuur (vir my )?(asseblief )?(die )?geld\b",  # af
        # Verbs take object/subject prefixes and suffixes ("ungithumelele" = "send me"), so match the stem.
        r"\b\w*(thumel|tfumel)\w*\b.{0,30}\bi?mali\b",  # zu, xh, ss, nr
        r"\b\w*(romel|thomel)\w*\b.{0,30}\b(chelete|tšhelete|tshelete|madi)\b",  # st, tn, nso
        r"\b\w*rhumel\w*\b.{0,30}\bmali\b",  # ts
        r"\b\w*(rumel|thumel)\w*\b.{0,30}\btshelede\b",  # ve
    ),
    "urgent": (
        r"\b(dringend|onmiddellik|nou dadelik|vandag nog)\b",  # af
        r"\b(ngokushesha|masinyane|ngekushesha)\b",  # zu, ss
        r"\b(ngokukhawuleza|khawuleza)\b",  # xh
        r"\b(kapele|ka pela|ka bonako|hang hang)\b",  # st, tn, nso
        r"\bhi ku hatlisa\b",  # ts
        r"\bnga u ṱavhanya\b",  # ve
    ),
    "secrecy": (
        r"\bmoenie (vir )?(iemand|niemand|pa|ma|die bank)\b.{0,20}\b(sê|vertel)\b",  # af
        r"\bungatsheli (muntu|bani|baba|mama)\b",  # zu
        r"\bungaxeleli (mntu|bani|tata|mama)\b",  # xh
        r"\b(o se ke wa bolella|se bolelle) (motho|mang)\b",  # st
    ),
}

RULES: tuple[Rule, ...] = (
    Rule(
        "otp_request", "Asks for an OTP or PIN",
        "Real banks, SARS and cellphone networks never ask you to share a one-time PIN, PIN or password.",
        0.75,
        (r"\b(otp|one[- ]time ?pin|one[- ]time ?password|verification code|pin code|your pin|cvv|cvc)\b",
         r"\b(send|share|give|forward|read)\b.{0,30}\b(code|otp|pin)\b"),
        "otp_fraud",
    ),
    Rule(
        "family_emergency", "Possible 'family member in trouble' scam",
        "Messages like 'Mom, I lost my phone, this is my new number' are a very common South African scam.",
        0.6,
        (r"\b(this is my new number|new number|lost my phone|phone (got )?stolen|my phone (is )?broke)\b",
         r"\b(i'?m in trouble|i am in trouble|i need help urgently|stuck at|accident|hospital|arrested)\b",
         *ML["new_number"]),
        "family_impersonation",
    ),
    Rule(
        "money_request", "Asks you to send money",
        "Requests to pay, transfer or send vouchers/airtime are the end-goal of most scams.",
        0.45,
        (r"\b(send|transfer|pay|deposit|e-?wallet|cash ?send|instant money|blue voucher|1voucher|ott voucher|"
         r"airtime|gift ?card|crypto|bitcoin|usdt)\b.{0,40}\b(r ?\d|money|amount|asap|now|today|me)\b",
         r"\bpay(ment)? (of|to)\b|\bsettle (the|your) (fee|fine|amount)\b",
         r"\b(e-?wallet|cash ?send|instant money)\b",
         *ML["send_money"]),
        "money_request",
    ),
    Rule(
        "urgency", "Creates urgency or fear",
        "Scammers rush you so you don't stop to check. Real organisations give you time.",
        0.3,
        (r"\b(urgent(ly)?|immediately|within (24|48) ?(hours|hrs)|today only|final (notice|warning|reminder)|"
         r"last chance|act now|asap|expires? (today|soon)|right now)\b",
         r"\b(account|card|profile|service).{0,30}\b(suspend(ed)?|block(ed)?|frozen|locked|deactivat(ed|ion)|closed)\b",
         r"\b(arrest|warrant|legal action|summons|court|blacklist(ed)?)\b",
         *ML["urgent"]),
    ),
    Rule(
        "prize_lottery", "Unexpected prize, refund or grant",
        "If you didn't enter a competition or apply for a refund, a 'you have won' message is a scam.",
        0.45,
        (r"\b(you('ve| have)? won|winner|congratulations|lucky draw|prize|jackpot|lottery|lotto)\b",
         r"\b(sars|tax) refund\b|\bunclaimed (funds|money|refund)\b|\b(srd|r350|r370) grant\b"),
        "prize_scam",
    ),
    Rule(
        "job_offer", "Too-good-to-be-true job offer",
        "Fake jobs often ask for an 'admin fee', ask you to 'like videos' for money, or come via WhatsApp/Telegram.",
        0.4,
        (r"\b(work from home|earn (r ?\d+|\d+ rand)|daily (income|pay)|part[- ]time (job|work)|recruit(ing|er)|"
         r"hiring now|like (videos|posts)|telegram)\b.{0,60}\b(earn|salary|commission|per (day|hour|task)|r ?\d)\b",
         r"\b(registration|admin|uniform|training) fee\b"),
        "job_scam",
    ),
    Rule(
        "investment", "Investment or crypto 'guaranteed returns'",
        "No real investment guarantees high returns. These are often Ponzi or crypto scams.",
        0.5,
        (r"\b(guaranteed|double your|100%|risk[- ]free)\b.{0,40}\b(returns?|profit|money|investment)\b",
         r"\b(forex|crypto|bitcoin|trading) (signals|account manager|mentor|platform)\b"),
        "investment_scam",
    ),
    Rule(
        "delivery_fee", "Fake parcel delivery fee",
        "Courier scams ask for a small 'customs' or 'redelivery' fee to steal your card details.",
        0.45,
        (r"\b(parcel|package|delivery|shipment|courier)\b.{0,60}\b(fee|pay|customs|on hold|failed|reschedule|address)\b",),
        "delivery_scam",
    ),
    Rule(
        "credential_link", "Asks you to log in or 'verify' via a link",
        "Phishing links lead to fake login pages that steal your banking or email passwords.",
        0.45,
        (r"\b(verify|confirm|update|validate|unlock|reactivate)\b.{0,40}\b(account|details|identity|banking|profile|information)\b",
         r"\b(click|tap|visit|log ?in|sign ?in)\b.{0,30}\b(link|here|below|https?://)\b"),
        "phishing",
    ),
    Rule(
        "secrecy", "Asks you to keep it secret",
        "Being told not to tell anyone, or not to call the bank, is a strong scam signal.",
        0.45,
        (r"\b(don'?t|do not) (tell|call|inform|share with) (anyone|anybody|the bank|your family|mom|dad)\b",
         r"\b(keep (this|it) (secret|between us|confidential))\b",
         *ML["secrecy"]),
    ),
    Rule(
        "remote_access", "Asks you to install an app or share your screen",
        "Apps like AnyDesk or TeamViewer let scammers control your phone and banking app.",
        0.65,
        (r"\b(anydesk|teamviewer|quick ?support|rustdesk|screen ?shar(e|ing)|remote access|install (this|the) app)\b",),
        "remote_access",
    ),
    Rule(
        "sim_swap", "Mentions SIM swap or number porting",
        "SIM-swap fraud lets criminals receive your bank OTPs. Contact your network immediately if unexpected.",
        0.4,
        (r"\b(sim ?swap|sim card (upgrade|replacement)|port(ing)? your number|rica)\b",),
        "sim_swap",
    ),
    Rule(
        "romance", "Possible romance scam",
        "Online partners you've never met in person who need money for emergencies or travel are a classic scam.",
        0.35,
        (r"\b(my love|my dear|sweetheart|darling|honey)\b.{0,80}\b(send|money|help|customs|flight|ticket|hospital)\b",),
        "romance_scam",
    ),
)

URL_RE = re.compile(r"\b((?:https?://|www\.)[^\s<>\"']+|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:co\.za|org\.za|gov\.za|com|net|org|xyz|top|click|link|info|online|site|live|shop|ly|me|io|cc|tk|ml|ga|cf|gq)(?:/[^\s<>\"']*)?)", re.I)
PHONE_RE = re.compile(r"(?:\+27|0027|\b0)[\s-]?\(?\d{2}\)?[\s-]?\d{3}[\s-]?\d{4}\b")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
AMOUNT_RE = re.compile(r"\bR\s?\d[\d\s,]*(?:\.\d{2})?\b|\b\d[\d\s,]*(?:\.\d{2})?\s?(?:rand|zar)\b", re.I)


def extract_entities(text: str) -> ExtractedEntities:
    urls = [u.rstrip(".,);]") for u in URL_RE.findall(text) if not EMAIL_RE.fullmatch(u)]
    emails = EMAIL_RE.findall(text)
    # Don't treat the domain part of an email address as a link.
    email_domains = {e.split("@", 1)[1].lower() for e in emails}
    urls = [u for u in urls if u.lower() not in email_domains]
    return ExtractedEntities(
        urls=list(dict.fromkeys(urls))[:10],
        phone_numbers=list(dict.fromkeys(p.strip() for p in PHONE_RE.findall(text)))[:10],
        emails=list(dict.fromkeys(emails))[:10],
        amounts=list(dict.fromkeys(a.strip() for a in AMOUNT_RE.findall(text)))[:10],
    )


def mentioned_brands(text: str) -> list[str]:
    lowered = text.lower()
    return [b for b in SA_BRANDS if re.search(rf"\b{re.escape(b)}\b", lowered)]


def run_rules(text: str) -> tuple[list[Indicator], str | None]:
    """Return matched indicators and the most likely scam type."""
    lowered = " ".join(text.lower().split())
    indicators: list[Indicator] = []
    scam_type: str | None = None
    best_weight = 0.0

    for rule in RULES:
        if any(re.search(p, lowered) for p in rule.patterns):
            indicators.append(
                Indicator(code=rule.code, title=rule.title, detail=rule.detail, weight=rule.weight, source="rules")
            )
            if rule.scam_type and rule.weight > best_weight:
                scam_type, best_weight = rule.scam_type, rule.weight

    brands = mentioned_brands(lowered)
    if brands and indicators:
        # A brand name alone is harmless; a brand name plus pressure tactics is impersonation.
        indicators.append(
            Indicator(
                code="brand_impersonation",
                title=f"Claims to be from {brands[0].title()}",
                detail="Scammers pretend to be trusted South African organisations. Check through the official app or website.",
                weight=0.25,
                source="rules",
            )
        )
        scam_type = scam_type or "brand_impersonation"

    return indicators, scam_type
