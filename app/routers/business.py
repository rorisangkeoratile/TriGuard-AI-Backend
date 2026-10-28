"""Mobile app: dashboard, screened calls, request checks, business directory, scam reports and audit log.

Everything is limited to the signed-in user's business, and for everyone except owners, to their own branch.
"""

from datetime import UTC, datetime, time, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session

from app.database import get_session
from app.mobile_schemas import (
    AuditEventResponse,
    CallResponse,
    DashboardResponse,
    DirectoryEntryIn,
    DirectoryEntryResponse,
    RequestCheckRequest,
    RiskResult,
    ScamReportRequest,
    ScamReportResponse,
)
from app.models import (
    APPROVER_ROLES,
    AuditEvent,
    Branch,
    Call,
    CallCategory,
    DirectoryEntry,
    Role,
    ScamReport,
    User,
    VerifyRequest,
    VerifyStatus,
)
from app.routers.deps import Actor, current_actor, require_roles
from app.services.accounts import audit, branch_label, visible_branch_id
from app.services.calls import call_response, mask_number, normalise_numbers
from app.services.numbers import InvalidNumberError, normalise
from app.services.privacy import redact
from app.services.request_check import check_request

router = APIRouter(tags=["mobile: business"])

SAST = timezone(timedelta(hours=2), "SAST")  # South Africa has no daylight saving


def scoped(stmt: Select, model, user: User) -> Select:
    """Limit a query to the user's business and, unless they see every branch, their branch (plus records that
    belong to no particular branch)."""
    stmt = stmt.where(model.business_id == user.business_id)
    branch_id = visible_branch_id(user)
    if branch_id is not None:
        stmt = stmt.where(or_(model.branch_id == branch_id, model.branch_id.is_(None)))
    return stmt


def _as_utc(value: datetime | None) -> datetime | None:
    """Times without a timezone are South African time (a date on its own means midnight)."""
    if value is None:
        return None
    return (value if value.tzinfo else value.replace(tzinfo=SAST)).astimezone(UTC)


def _until(value: datetime) -> datetime:
    """End of a `to` filter: a date on its own includes that whole day."""
    whole_day = value.tzinfo is None and value.time() == time()
    return _as_utc(value) + (timedelta(days=1) if whole_day else timedelta())


def _visible_call(db: Session, call_id: str, user: User) -> Call:
    call = db.scalar(scoped(select(Call).where(Call.id == call_id), Call, user))
    if call is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "We couldn't find that call.")
    return call


# --- Dashboard and calls ----------------------------------------------------------------------------------


@router.get("/dashboard", response_model=DashboardResponse)
def dashboard(actor: Actor = Depends(current_actor), db: Session = Depends(get_session)) -> DashboardResponse:
    user = actor.user
    start_of_day = datetime.combine(datetime.now(SAST).date(), time(), SAST).astimezone(UTC)
    today = scoped(select(Call.category, Call.risk), Call, user).where(Call.received_at >= start_of_day,
                                                                      Call.category != CallCategory.direct_call)
    rows = db.execute(today).all()
    pending = db.scalar(scoped(select(func.count()).select_from(VerifyRequest), VerifyRequest, user).where(
        VerifyRequest.status == VerifyStatus.pending, VerifyRequest.expires_at > datetime.now(UTC)))
    alerts = db.scalars(scoped(select(Call), Call, user).where(
        or_(Call.risk.in_(["high", "medium"]), Call.category.in_([CallCategory.silent_call,
                                                                   CallCategory.blocked_number]))
    ).order_by(Call.received_at.desc()).limit(5))
    connected = bool(user.business.screening_number)
    return DashboardResponse(
        calls_screened_today=len(rows),
        high_risk_calls_today=sum(1 for c, r in rows if r == "high" and c == CallCategory.screened),
        silent_calls_blocked_today=sum(1 for c, _ in rows if c == CallCategory.silent_call),
        scam_numbers_blocked_today=sum(1 for c, _ in rows if c == CallCategory.blocked_number),
        verify_requests_pending=pending or 0,
        system_status="Screening is ON" if connected else "Your TriGuard number isn't connected yet",
        system_status_ok=connected,
        recent_alerts=[call_response(c, user) for c in alerts],
    )


@router.get("/calls", response_model=list[CallResponse])
def list_calls(
    risk: Literal["high", "medium", "low", "blocked", "silent"] | None = Query(None),
    from_: datetime | None = Query(None, alias="from", description="ISO date or time (South African time if no zone)."),
    to: datetime | None = Query(None),
    branch: str | None = Query(None, description="Branch id or name (owners only; others see their own branch)."),
    limit: int = Query(100, ge=1, le=500),
    actor: Actor = Depends(current_actor),
    db: Session = Depends(get_session),
) -> list[CallResponse]:
    stmt = scoped(select(Call), Call, actor.user)
    if risk == "blocked":
        stmt = stmt.where(Call.category == CallCategory.blocked_number)
    elif risk == "silent":
        stmt = stmt.where(Call.category == CallCategory.silent_call)
    elif risk:
        stmt = stmt.where(Call.risk == risk)
    if from_:
        stmt = stmt.where(Call.received_at >= _as_utc(from_))
    if to:
        stmt = stmt.where(Call.received_at < _until(to))
    if branch:
        stmt = stmt.join(Branch, Call.branch_id == Branch.id).where(or_(Branch.id == branch, Branch.name == branch))
    calls = db.scalars(stmt.order_by(Call.received_at.desc()).limit(limit))
    return [call_response(c, actor.user) for c in calls]


@router.get("/calls/{call_id}", response_model=CallResponse)
def get_call(call_id: str, actor: Actor = Depends(current_actor), db: Session = Depends(get_session)) -> CallResponse:
    return call_response(_visible_call(db, call_id, actor.user), actor.user)


@router.post("/request-check", response_model=RiskResult)
def request_check(body: RequestCheckRequest, actor: Actor = Depends(current_actor),
                  db: Session = Depends(get_session)) -> RiskResult:
    """Staff tap what the caller is asking for; TriGuard says how risky it is and what to do. Nothing is stored."""
    call = _visible_call(db, body.call_id, actor.user) if body.call_id else None
    return check_request(body.request_types, body.note, call)


# --- Directory --------------------------------------------------------------------------------------------


def directory_response(entry: DirectoryEntry, viewer: User) -> DirectoryEntryResponse:
    linked = entry.user
    return DirectoryEntryResponse(
        id=entry.id, name=entry.name, role_or_company=entry.role_or_company, category=entry.category,
        aliases=entry.aliases or [], verified_phone_numbers=entry.phone_numbers or [],
        trusted_backup_contact_name=entry.backup_contact_name,
        trusted_backup_contact_phone=entry.backup_contact_phone,
        bank_reference=entry.bank_reference if viewer.role != Role.staff else None,
        notes=entry.notes, branch=branch_label(entry.branch), branch_id=entry.branch_id, user_id=entry.user_id,
        can_approve_verify=linked is not None and linked.is_active and linked.role in APPROVER_ROLES,
    )


def _apply_entry(db: Session, entry: DirectoryEntry, body: DirectoryEntryIn, owner: User) -> None:
    if body.branch_id and db.scalar(select(Branch.id).where(Branch.id == body.branch_id,
                                                            Branch.business_id == owner.business_id)) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "That branch doesn't exist.")
    if body.user_id and db.scalar(select(User.id).where(User.id == body.user_id,
                                                        User.business_id == owner.business_id)) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "That staff account doesn't exist.")
    try:
        numbers = normalise_numbers(body.verified_phone_numbers)
        backup = normalise_numbers([body.trusted_backup_contact_phone or ""])
    except InvalidNumberError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    entry.name = body.name.strip()
    entry.role_or_company = body.role_or_company.strip()
    entry.category = body.category
    entry.aliases = [a.strip() for a in body.aliases if a.strip()]
    entry.phone_numbers = numbers
    entry.backup_contact_name = body.trusted_backup_contact_name
    entry.backup_contact_phone = backup[0] if backup else None
    entry.bank_reference = body.bank_reference
    entry.notes = body.notes
    entry.branch_id = body.branch_id
    entry.user_id = body.user_id


def _owned_entry(db: Session, entry_id: str, user: User) -> DirectoryEntry:
    entry = db.get(DirectoryEntry, entry_id)
    if entry is None or entry.business_id != user.business_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "We couldn't find that person or supplier.")
    return entry


@router.get("/directory", response_model=list[DirectoryEntryResponse])
def list_directory(
    q: str | None = Query(None, max_length=100, description="Search names, aliases and companies."),
    branch: str | None = Query(None, description="Branch id."),
    actor: Actor = Depends(current_actor),
    db: Session = Depends(get_session),
) -> list[DirectoryEntryResponse]:
    stmt = scoped(select(DirectoryEntry), DirectoryEntry, actor.user)
    if branch:
        stmt = stmt.where(or_(DirectoryEntry.branch_id == branch, DirectoryEntry.branch_id.is_(None)))
    entries = db.scalars(stmt.order_by(DirectoryEntry.name))
    if q:
        needle = q.strip().lower()
        entries = [e for e in entries
                   if needle in " ".join([e.name, e.role_or_company, *(e.aliases or [])]).lower()]
    return [directory_response(e, actor.user) for e in entries]


@router.post("/directory", response_model=DirectoryEntryResponse, status_code=status.HTTP_201_CREATED)
def add_directory_entry(body: DirectoryEntryIn, actor: Actor = Depends(require_roles(Role.owner)),
                        db: Session = Depends(get_session)) -> DirectoryEntryResponse:
    entry = DirectoryEntry(business_id=actor.user.business_id)
    _apply_entry(db, entry, body, actor.user)
    db.add(entry)
    audit(db, "DIRECTORY_ADDED", f"{actor.user.name} added {entry.name} to the directory", user=actor.user,
          branch_id=entry.branch_id)
    db.commit()
    return directory_response(entry, actor.user)


@router.put("/directory/{entry_id}", response_model=DirectoryEntryResponse)
def update_directory_entry(entry_id: str, body: DirectoryEntryIn, actor: Actor = Depends(require_roles(Role.owner)),
                           db: Session = Depends(get_session)) -> DirectoryEntryResponse:
    entry = _owned_entry(db, entry_id, actor.user)
    numbers_before = list(entry.phone_numbers or [])
    _apply_entry(db, entry, body, actor.user)
    changed = " (phone numbers changed)" if numbers_before != entry.phone_numbers else ""
    audit(db, "DIRECTORY_UPDATED", f"{actor.user.name} updated {entry.name}{changed}", user=actor.user,
          branch_id=entry.branch_id)
    db.commit()
    return directory_response(entry, actor.user)


@router.delete("/directory/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_directory_entry(entry_id: str, actor: Actor = Depends(require_roles(Role.owner)),
                           db: Session = Depends(get_session)) -> Response:
    entry = _owned_entry(db, entry_id, actor.user)
    audit(db, "DIRECTORY_REMOVED", f"{actor.user.name} removed {entry.name} from the directory", user=actor.user,
          branch_id=entry.branch_id)
    db.delete(entry)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Scam reports and audit -------------------------------------------------------------------------------


@router.post("/scam-reports", response_model=ScamReportResponse, status_code=status.HTTP_201_CREATED)
def report_scam_number(body: ScamReportRequest, actor: Actor = Depends(current_actor),
                       db: Session = Depends(get_session)) -> ScamReportResponse:
    """Report a scam number. It joins the shared TriGuard list once it has been reviewed."""
    try:
        e164, _ = normalise(body.number)
    except InvalidNumberError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    call_id = _visible_call(db, body.call_id, actor.user).id if body.call_id else None

    duplicate = db.scalar(select(ScamReport.id).where(
        ScamReport.business_id == actor.user.business_id, ScamReport.reported_by_id == actor.user.id,
        ScamReport.number == e164, ScamReport.created_at > datetime.now(UTC) - timedelta(hours=24)))
    if duplicate:
        return ScamReportResponse(report_id=duplicate, number=mask_number(e164), accepted=False,
                                  status="pending_review", message="You've already reported this number today.")

    report = ScamReport(business_id=actor.user.business_id, reported_by_id=actor.user.id, number=e164,
                        reason=redact(body.reason.strip()), call_id=call_id)
    db.add(report)
    audit(db, "SCAM_NUMBER_REPORTED", f"{actor.user.name} reported {mask_number(e164)} as a scam number",
          user=actor.user)
    db.commit()
    return ScamReportResponse(report_id=report.id, number=mask_number(e164), accepted=True, status=report.status,
                              message="Thank you. TriGuard will check this number and warn other businesses.")


@router.get("/audit", response_model=list[AuditEventResponse])
def audit_log(
    from_: datetime | None = Query(None, alias="from"),
    to: datetime | None = Query(None),
    type: str | None = Query(None, max_length=50, description="Event type, e.g. SIGN_IN_FAILED."),
    limit: int = Query(200, ge=1, le=1000),
    actor: Actor = Depends(require_roles(Role.owner, Role.manager)),
    db: Session = Depends(get_session),
) -> list[AuditEventResponse]:
    stmt = scoped(select(AuditEvent), AuditEvent, actor.user)
    if from_:
        stmt = stmt.where(AuditEvent.created_at >= _as_utc(from_))
    if to:
        stmt = stmt.where(AuditEvent.created_at < _until(to))
    if type:
        stmt = stmt.where(AuditEvent.event_type == type.upper())
    branches = {b.id: b for b in db.scalars(select(Branch).where(Branch.business_id == actor.user.business_id))}
    return [
        AuditEventResponse(id=e.id, timestamp=e.created_at, event_type=e.event_type, summary=e.summary,
                           actor_name=e.actor_name, actor_role=e.actor_role,
                           branch=branch_label(branches.get(e.branch_id)), details=e.details)
        for e in db.scalars(stmt.order_by(AuditEvent.created_at.desc()).limit(limit))
    ]
