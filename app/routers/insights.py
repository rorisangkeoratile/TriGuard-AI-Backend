from fastapi import APIRouter
from fastapi.concurrency import run_in_threadpool

from app import db
from app.routers.numbers import trending
from app.schemas import InsightsResponse, NumberReportCategory, ScamTypeCount
from app.services.numbers import category_label

router = APIRouter(prefix="/api/v1", tags=["insights"])


@router.get("/insights", response_model=InsightsResponse)
async def insights() -> InsightsResponse:
    """Community dashboard: today's checks, reports this week, top scam types and most-reported numbers."""
    counts = await run_in_threadpool(db.insight_counts)
    return InsightsResponse(
        checks_today=counts["checks_today"],
        scams_detected_today=counts["scams_detected_today"],
        reports_this_week=counts["reports_this_week"],
        top_scam_types=[
            ScamTypeCount(category=NumberReportCategory(cat), label=category_label(cat), count=n)
            for cat, n in counts["report_categories"][:5]
        ],
        most_reported=await run_in_threadpool(trending, 5),
    )
