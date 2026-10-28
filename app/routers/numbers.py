from datetime import datetime

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.concurrency import run_in_threadpool

from app import db
from app.languages import normalise_language
from app.schemas import (
    NumberLookupResponse,
    NumberReportCategory,
    NumberReportRequest,
    NumberReportResponse,
    ReportedNumber,
)
from app.services.localize import localize
from app.services.numbers import InvalidNumberError, category_label, lookup, normalise
from app.services.privacy import redact

router = APIRouter(prefix="/api/v1/numbers", tags=["numbers"])


@router.get("/lookup", response_model=NumberLookupResponse)
async def lookup_number(
    number: str = Query(..., min_length=3, max_length=32, examples=["0710000001"]),
    language: str = Query("en", description="Language for the result."),
) -> NumberLookupResponse:
    """Truecaller-style check: has the TriGuard community reported this number?"""
    try:
        result = await run_in_threadpool(lookup, number)
    except InvalidNumberError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    await run_in_threadpool(db.record_check, "number", result.risk_level.value)
    # User comments stay as written; everything else is translated.
    return await localize(result, normalise_language(language))


@router.post("/report", response_model=NumberReportResponse, status_code=status.HTTP_201_CREATED)
def report_number(body: NumberReportRequest, request: Request) -> NumberReportResponse:
    """Report a scam number to warn other users. Reports are anonymous."""
    try:
        e164, _ = normalise(body.number)
    except InvalidNumberError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc

    client_ip = request.client.host if request.client else None
    accepted = db.add_report(
        e164, body.category.value, body.channel, redact((body.comment or "").strip()) or None,
        db.hash_reporter(body.reporter_id, client_ip),
    )
    return NumberReportResponse(
        number=e164,
        accepted=accepted,
        message="Thank you - your report helps protect other South Africans." if accepted
        else "You've already reported this number today.",
    )


@router.get("/trending", response_model=list[ReportedNumber])
def trending(limit: int = Query(10, ge=1, le=50)) -> list[ReportedNumber]:
    """Most-reported numbers in the last 30 days (for a 'scam alerts near you' feed)."""
    return [
        ReportedNumber(
            number=row["number"],
            total_reports=row["total"],
            top_category=NumberReportCategory(row["top_category"]),
            top_category_label=category_label(row["top_category"]),
            last_reported_at=datetime.fromisoformat(row["last_at"]),
        )
        for row in db.top_reported(limit)
    ]
