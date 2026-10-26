"""Link (URL) risk checks: lookalike domains, shorteners, raw IPs and optional Google Safe Browsing."""

import ipaddress
import logging
import re
from urllib.parse import urlsplit

import httpx

from app.config import get_settings
from app.schemas import Indicator, LinkCheckResult
from app.services import risk

log = logging.getLogger(__name__)

# Official domains of organisations commonly impersonated in South Africa.
OFFICIAL_DOMAINS = {
    "fnb": "fnb.co.za",
    "capitec": "capitecbank.co.za",
    "absa": "absa.co.za",
    "standardbank": "standardbank.co.za",
    "nedbank": "nedbank.co.za",
    "tymebank": "tymebank.co.za",
    "discovery": "discovery.co.za",
    "africanbank": "africanbank.co.za",
    "investec": "investec.com",
    "sars": "sars.gov.za",
    "sassa": "sassa.gov.za",
    "homeaffairs": "dha.gov.za",
    "nsfas": "nsfas.org.za",
    "postoffice": "postoffice.co.za",
    "vodacom": "vodacom.co.za",
    "mtn": "mtn.co.za",
    "telkom": "telkom.co.za",
    "takealot": "takealot.com",
    "dhl": "dhl.com",
    "netflix": "netflix.com",
    "dstv": "dstv.com",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at",
    "t.ly", "tiny.cc", "s.id", "rebrand.ly", "v.gd", "qrco.de",
}

RISKY_TLDS = {
    "xyz", "top", "click", "link", "online", "site", "live", "shop", "info", "icu", "buzz", "rest", "cfd", "sbs",
    "tk", "ml", "ga", "cf", "gq", "zip", "mov", "country", "support", "loan", "work",
}

SUSPICIOUS_WORDS = ("login", "verify", "secure", "update", "account", "banking", "otp", "refund", "claim", "wallet")


def _normalise(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        url = "http://" + url
    return url


def _levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _registered_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "org", "gov", "ac", "net", "web"} and parts[-1] == "za":
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def heuristic_indicators(url: str) -> tuple[list[Indicator], str | None]:
    parts = urlsplit(_normalise(url))
    host = (parts.hostname or "").lower().rstrip(".")
    indicators: list[Indicator] = []
    if not host:
        return [Indicator(code="invalid_url", title="Not a valid link", detail="This doesn't look like a web address.",
                          weight=0.2, source="link")], None

    def add(code: str, title: str, detail: str, weight: float) -> None:
        indicators.append(Indicator(code=code, title=title, detail=detail, weight=weight, source="link"))

    try:
        ipaddress.ip_address(host)
        add("raw_ip", "Uses a number instead of a name",
            "Legitimate companies use a domain name, not a raw IP address.", 0.5)
    except ValueError:
        pass

    if host.startswith("xn--") or ".xn--" in host:
        add("punycode", "Hidden look-alike characters",
            "The address uses special characters that can imitate a real website's name.", 0.55)

    if "@" in parts.netloc:
        add("userinfo_trick", "Misleading address",
            "Text before an '@' in a link is ignored - the real site is what comes after it.", 0.5)

    registered = _registered_domain(host)
    tld = host.rsplit(".", 1)[-1]

    if registered in SHORTENERS or host in SHORTENERS:
        add("shortener", "Shortened link hides the real destination",
            "Scammers use link shorteners so you can't see where the link really goes.", 0.3)

    if tld in RISKY_TLDS:
        add("risky_tld", f"Unusual web address ending (.{tld})",
            f"'.{tld}' addresses are cheap and often used for scams. SA banks and government use .co.za / .gov.za.", 0.3)

    if parts.scheme == "http":
        add("no_https", "Not a secure (https) link", "Never enter passwords or card details on a non-https page.", 0.15)

    if host.count(".") >= 4 or host.count("-") >= 3:
        add("complex_host", "Unusually long or complex address",
            "Very long addresses with many dots or dashes are often used to disguise fake sites.", 0.2)

    path_and_query = (parts.path + "?" + parts.query).lower()
    if sum(w in host or w in path_and_query for w in SUSPICIOUS_WORDS) >= 2:
        add("credential_words", "Asks you to log in or verify",
            "Words like 'verify', 'login' and 'account' in a link are typical of phishing pages.", 0.2)

    impersonated: str | None = None
    compact_host = host.replace("-", "").replace(".", "")
    for brand, official in OFFICIAL_DOMAINS.items():
        if registered == official or host.endswith("." + official):
            return [], brand  # Official site - clear any heuristic noise.
        label = registered.split(".")[0].replace("-", "")
        if brand in compact_host or (len(brand) >= 5 and _levenshtein(label, brand) <= 1):
            impersonated = brand
            add("brand_lookalike", f"Pretends to be {brand.upper() if len(brand) <= 4 else brand.title()}",
                f"This is not the official site. The real one is {official}.", 0.7)
            break

    return indicators, impersonated


async def safe_browsing_lookup(url: str) -> Indicator | None:
    key = get_settings().google_safe_browsing_api_key
    if not key:
        return None
    body = {
        "client": {"clientId": "triguard-ai", "clientVersion": "0.1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": _normalise(url)}],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}", json=body
            )
            resp.raise_for_status()
            matches = resp.json().get("matches", [])
    except httpx.HTTPError as exc:
        log.warning("Safe Browsing lookup failed: %s", exc)
        return None
    if not matches:
        return None
    threat = matches[0].get("threatType", "UNKNOWN").replace("_", " ").lower()
    return Indicator(
        code="known_malicious", title="Listed as dangerous by Google Safe Browsing",
        detail=f"This link is on a global blocklist for {threat}.", weight=0.95, source="reputation",
    )


async def check_link(url: str) -> LinkCheckResult:
    indicators, _ = heuristic_indicators(url)
    reputation = await safe_browsing_lookup(url)
    if reputation:
        indicators.insert(0, reputation)

    score = risk.score_from_indicators(indicators)
    level = risk.score_to_level(score)
    host = urlsplit(_normalise(url)).hostname
    return LinkCheckResult(
        url=url,
        domain=host,
        reputation_checked=bool(get_settings().google_safe_browsing_api_key),
        risk_level=level,
        risk_score=score,
        headline=risk.headline("link", level),
        summary=(
            "We found warning signs in this link." if indicators else
            "We didn't find warning signs, but always type bank and government addresses yourself."
        ),
        indicators=indicators,
        advice=risk.build_advice("link", level),
    )
