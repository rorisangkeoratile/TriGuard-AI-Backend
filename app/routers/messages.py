from fastapi import APIRouter, File, Form, HTTPException, UploadFile, status
from fastapi.concurrency import run_in_threadpool

from app import db
from app.languages import normalise_language
from app.routers.uploads import read_upload
from app.schemas import LinkCheckRequest, LinkCheckResult, MessageAnalysisRequest, MessageAnalysisResponse
from app.services import llm
from app.services.email_analysis import email_indicators, impersonation_indicators, parse_email
from app.services.links import check_link
from app.services.localize import localize
from app.services.message_analysis import analyse_message

router = APIRouter(prefix="/api/v1", tags=["messages"])

IMAGE_TYPES = {"image/png", "image/jpeg", "image/webp", "image/gif"}


async def _counted(result: MessageAnalysisResponse) -> MessageAnalysisResponse:
    await run_in_threadpool(db.record_check, result.kind, result.risk_level.value, result.scam_type)
    return result


@router.post("/messages/analyze", response_model=MessageAnalysisResponse)
async def analyze_message(body: MessageAnalysisRequest) -> MessageAnalysisResponse:
    """Check an SMS, email body, social media DM or any text the user pasted or shared into TriGuard."""
    return await _counted(await analyse_message(
        body.text, channel=body.channel.value, sender=body.sender, language=body.language
    ))


@router.post("/messages/screenshot", response_model=MessageAnalysisResponse)
async def analyze_screenshot(
    file: UploadFile = File(..., description="Screenshot of a suspicious message (png, jpeg, webp)."),
    language: str = Form("auto", description="Result language, or 'auto' for the message's own language."),
) -> MessageAnalysisResponse:
    """Read a screenshot of a message (e.g. shared from any chat app) and check it for scam signs."""
    if not llm.llm_available():
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Screenshot reading needs the AI service to be configured.")
    data = await read_upload(file, allowed_prefixes=("image/",))
    media_type = (file.content_type or "image/png").lower()
    if media_type not in IMAGE_TYPES:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "Use a PNG, JPEG, WebP or GIF screenshot.")
    result = await analyse_message("", channel="screenshot", language=language, kind="screenshot",
                                   image=(data, media_type))
    if not result.ai_used:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "We couldn't read this screenshot. Try pasting the text instead.")
    return await _counted(result)


@router.post("/email/analyze", response_model=MessageAnalysisResponse)
async def analyze_email(
    file: UploadFile | None = File(None, description="A saved email (.eml) - includes headers for spoofing checks."),
    raw: str | None = Form(None, description="Raw email source ('Show original' in Gmail), or just the email text."),
    language: str = Form("auto", description="Result language, or 'auto' for the email's own language."),
    recipient_domain: str | None = Form(None, max_length=253, description=(
        "The checking user's own email domain (not their address), to spot look-alike domains and outsiders "
        "posing as executives.")),
) -> MessageAnalysisResponse:
    """Check an email for phishing and CEO fraud: spoofed sender, failed SPF/DKIM/DMARC, look-alike domains,
    fake executives, "let's confirm on a video call", lying links, dangerous attachments."""
    if file is not None:
        data = await read_upload(file)
    elif raw:
        data = raw.encode()
    else:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Upload an .eml file or paste the email.")

    msg, body, links = parse_email(data)
    has_headers = bool(msg.get("From"))
    text = body if has_headers else data.decode(errors="replace")
    if has_headers and msg.get("Subject"):
        text = f"Subject: {msg['Subject']}\n\n{text}"
    if not text.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "We couldn't find any text in this email.")

    return await _counted(await analyse_message(
        text[:20_000],
        channel="email",
        sender=str(msg.get("From")) if has_headers else None,
        language=language,
        kind="email",
        extra_indicators=(email_indicators(msg, links) if has_headers else [])
        + impersonation_indicators(msg, text, recipient_domain),
    ))


@router.post("/links/check", response_model=LinkCheckResult)
async def check_link_endpoint(body: LinkCheckRequest) -> LinkCheckResult:
    """Check a link before opening it: look-alike bank/government sites, shorteners, blocklists."""
    return await localize(await check_link(body.url), normalise_language(body.language))
