"""Email-specific checks: sender spoofing, failed SPF/DKIM/DMARC, Reply-To tricks and risky attachments."""

import re
from difflib import SequenceMatcher
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser

from app.schemas import Indicator
from app.services.links import OFFICIAL_DOMAINS, _registered_domain
from app.services.scam_rules import SA_BRANDS

RISKY_ATTACHMENTS = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".iso", ".img", ".html", ".htm", ".hta",
                     ".lnk", ".msi", ".jar", ".zip", ".rar", ".7z", ".docm", ".xlsm")
FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "icloud.com", "proton.me",
             "protonmail.com", "mail.com", "gmx.com", "webmail.co.za", "mweb.co.za", "telkomsa.net"}


class _LinkTextParser(HTMLParser):
    """Collects (visible text, real href) pairs so we can catch links whose text lies about the destination."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self.text_parts: list[str] = []
        self._href: str | None = None
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._buf = []

    def handle_endtag(self, tag):
        if tag == "a" and self._href:
            self.links.append(("".join(self._buf).strip(), self._href))
            self._href = None

    def handle_data(self, data):
        self.text_parts.append(data)
        if self._href is not None:
            self._buf.append(data)


def parse_email(raw: bytes) -> tuple[EmailMessage, str, list[tuple[str, str]]]:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    plain, html = "", ""
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        try:
            content = part.get_content()
        except (LookupError, ValueError):
            continue
        if ctype == "text/plain":
            plain += str(content)
        elif ctype == "text/html":
            html += str(content)

    links: list[tuple[str, str]] = []
    if html:
        parser = _LinkTextParser()
        parser.feed(html)
        links = parser.links
        if not plain:
            plain = " ".join(" ".join(parser.text_parts).split())
    body = plain or ""
    for _, href in links:
        if href.startswith("http") and href not in body:
            body += f"\n{href}"
    return msg, body, links


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower().strip(">") if "@" in address else ""


# Business email compromise: a "senior executive" asking for a payment, often followed by a video call.
EXECUTIVE = re.compile(
    r"\b(ceo|cfo|coo|chief (executive|financial|operating) officer|managing director|financial director|"
    r"finance director|group (ceo|cfo)|chairman|chairperson|chief executive|head of finance)\b", re.I)
MEETING = re.compile(
    r"teams\.microsoft\.com|teams\.live\.com|zoom\.us/(j|my)/|meet\.google\.com/|webex\.com/(meet|join)|"
    r"\b(teams|zoom|google meet|webex) (call|meeting)\b|\bvideo (call|conference|meeting)\b", re.I)


def _lookalike(sender: str, own: str) -> bool:
    """tfg-co.za or tfgroup.co for a company at tfg.co.za: similar to the company's domain but not it."""
    if not sender or not own or sender == own:
        return False
    name = own.split(".")[0]
    return (len(name) >= 3 and name in sender) or SequenceMatcher(None, sender, own).ratio() >= 0.8


def impersonation_indicators(msg: EmailMessage, body: str, recipient_domain: str | None) -> list[Indicator]:
    """Executive impersonation and "let's confirm on a call" - the pattern behind the 2024 Arup deepfake fraud."""
    indicators: list[Indicator] = []
    display_name, from_addr = parseaddr(str(msg.get("From", "")))
    sender = _registered_domain(_domain(from_addr)) if from_addr else ""
    own = _registered_domain(recipient_domain.lower().strip()) if recipient_domain else ""
    # The user's sign-in domain (e.g. *.onmicrosoft.com) can differ from the domain their organisation mails from.
    own_is_company = bool(own) and own not in FREE_MAIL and own != "onmicrosoft.com"
    # Microsoft 365 stamps mail sent from inside the organisation as internal, and strips this stamp from outside
    # mail, so it can't be faked by an external sender. It's the reliable "same organisation" test.
    internal = any(str(msg.get(h, "")).strip().lower() == "internal"
                   for h in ("X-MS-Exchange-Organization-AuthAs", "X-MS-Exchange-CrossTenant-AuthAs"))
    if internal:
        own_is_company = False
    claims_exec = EXECUTIVE.search(display_name) or EXECUTIVE.search(body[-600:])  # name or signature

    if own_is_company and _lookalike(sender, own):
        indicators.append(Indicator(
            code="lookalike_domain", title="Sent from a look-alike of your company's domain",
            detail=f"It comes from {sender}, which looks like your company's {own} but isn't. "
                   "Criminals register look-alike domains to impersonate staff.",
            weight=0.75, source="email_auth"))
    if claims_exec and sender:
        if sender in FREE_MAIL:
            indicators.append(Indicator(
                code="executive_freemail", title="Claims to be a senior executive, but uses a free email account",
                detail=f"A CEO or CFO wouldn't ask for payments from {sender}. This is the classic CEO-fraud set-up.",
                weight=0.7, source="email_auth"))
        elif own_is_company and sender != own:
            indicators.append(Indicator(
                code="executive_external", title="Claims to be a senior executive, but comes from outside your company",
                detail=f"It's signed as a senior person, but it's from {sender}, not your company's {own}.",
                weight=0.65, source="email_auth"))
    if MEETING.search(body):
        indicators.append(Indicator(
            code="meeting_link", title="Wants to confirm over a video call it set up",
            detail="A Teams or Zoom call set up by the sender is not proof: deepfake video and voice can impersonate "
                   "anyone on a call. In 2024 an Arup employee paid about US$25 million after a call like this. "
                   "Verify by calling the person on a number you already have.",
            weight=0.4, source="email_auth"))
    return indicators


def email_indicators(msg: EmailMessage, links: list[tuple[str, str]]) -> list[Indicator]:
    indicators: list[Indicator] = []

    def add(code: str, title: str, detail: str, weight: float) -> None:
        indicators.append(Indicator(code=code, title=title, detail=detail, weight=weight, source="email_auth"))

    display_name, from_addr = parseaddr(str(msg.get("From", "")))
    from_domain = _domain(from_addr)
    from_registered = _registered_domain(from_domain) if from_domain else ""

    auth = " ".join(str(h) for h in msg.get_all("Authentication-Results", []) or []).lower()
    for check in ("dmarc", "spf", "dkim"):
        if re.search(rf"\b{check}=(fail|softfail|permerror)", auth):
            add(f"{check}_fail", f"Email failed the {check.upper()} security check",
                "The sending server isn't authorised to send for this address - a sign the sender is faked.",
                0.6 if check == "dmarc" else 0.35)

    _, reply_addr = parseaddr(str(msg.get("Reply-To", "")))
    reply_domain = _domain(reply_addr)
    if reply_domain and from_domain and _registered_domain(reply_domain) != from_registered:
        add("reply_to_mismatch", "Replies go to a different address",
            f"It says it's from {from_domain}, but your reply would go to {reply_domain}.", 0.45)

    name_lower = display_name.lower()
    for brand in SA_BRANDS:
        if re.search(rf"\b{re.escape(brand)}\b", name_lower):
            official = OFFICIAL_DOMAINS.get(brand.replace(" ", ""))
            if from_registered in FREE_MAIL:
                add("brand_from_freemail", f"'{display_name}' is using a free email account",
                    f"{brand.title()} would never email you from {from_domain}.", 0.65)
            elif official and from_registered != official:
                add("brand_domain_mismatch", f"Claims to be {brand.title()} but isn't",
                    f"The email comes from {from_domain}, not the official {official}.", 0.6)
            break

    for text, href in links:
        shown = re.search(r"(?:https?://)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)", text.lower())
        real = re.search(r"https?://([^/:?#]+)", href.lower())
        if shown and real and _registered_domain(shown.group(1)) != _registered_domain(real.group(1)):
            add("link_text_mismatch", "A link lies about where it goes",
                f"The link shows '{shown.group(1)}' but actually opens '{real.group(1)}'.", 0.6)
            break

    for part in msg.iter_attachments():
        name = (part.get_filename() or "").lower()
        if name.endswith(RISKY_ATTACHMENTS):
            add("risky_attachment", f"Dangerous attachment ({name})",
                "This type of file can install malware or open a fake login page. Don't open it.", 0.55)
            break

    return indicators
