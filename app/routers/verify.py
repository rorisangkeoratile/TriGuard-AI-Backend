"""Guard 3: TriGuard Verify. A risky request is approved on the real person's own phone, never on the call.

- The person named in the request (a directory entry linked to a TriGuard account) must approve it.
- Payments above the business's threshold also need a second, different approver (owner, manager or finance).
- Nobody can approve their own request. Requests expire after 5 minutes.
"""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import Select, and_, or_, select
from sqlalchemy.orm import Session

from app.database import get_session
from app.mobile_schemas import ApprovalRecord, VerifyCreateRequest, VerifyRespondRequest, VerifyResponse
from app.models import (
    APPROVER_ROLES,
    Call,
    DirectoryEntry,
    Role,
    User,
    VerifyApproval,
    VerifyRequest,
    VerifyStatus,
)
from app.routers.business import scoped
from app.routers.deps import Actor, current_actor
from app.services.accounts import audit, branch_label, visible_branch_id
from app.services.privacy import redact

router = APIRouter(tags=["mobile: verify"])

VERIFY_TTL = timedelta(minutes=5)
SECOND_APPROVER = "a second approver (owner, manager or finance)"


def _target_user_id(req: VerifyRequest) -> str | None:
    return req.target_entry.user_id


def _expire_if_due(req: VerifyRequest) -> bool:
    if req.status == VerifyStatus.pending and req.expires_at <= datetime.now(UTC):
        req.status = VerifyStatus.expired
        req.decided_at = req.expires_at
        return True
    return False


def _second_approval(req: VerifyRequest) -> VerifyApproval | None:
    target = _target_user_id(req)
    return next((a for a in req.approvals if a.approver_id != target and a.decision == "approve"), None)


def can_respond(req: VerifyRequest, user: User) -> bool:
    if req.status != VerifyStatus.pending or req.expires_at <= datetime.now(UTC):
        return False
    if user.id == req.requested_by_id or user.role not in APPROVER_ROLES or not user.is_active:
        return False
    if any(a.approver_id == user.id for a in req.approvals):
        return False
    if user.id == _target_user_id(req):
        return True
    return req.requires_dual_approval and _second_approval(req) is None


def _waiting_for(req: VerifyRequest) -> list[str]:
    if req.status != VerifyStatus.pending:
        return []
    target = _target_user_id(req)
    waiting = [] if any(a.approver_id == target for a in req.approvals) else [req.target_entry.name]
    if req.requires_dual_approval and _second_approval(req) is None:
        waiting.append(SECOND_APPROVER)
    return waiting


def verify_response(req: VerifyRequest, viewer: User) -> VerifyResponse:
    return VerifyResponse(
        verify_id=req.id, status=req.status, target_person_id=req.target_entry_id,
        target_person_name=req.target_entry.name, target_person_role=req.target_entry.role_or_company,
        requested_by_id=req.requested_by_id, requested_by_name=req.requested_by.name,
        request_type=req.request_type, amount_rand=req.amount_rand, note=req.note, call_id=req.call_id,
        branch=branch_label(req.requested_by.branch),
        requires_dual_approval=req.requires_dual_approval,
        approvals=[ApprovalRecord(approver_id=a.approver_id, approver_name=a.approver.name, role=a.approver.role,
                                  decision=a.decision, timestamp=a.created_at) for a in req.approvals],
        waiting_for=_waiting_for(req), can_respond=can_respond(req, viewer),
        created_at=req.created_at, expires_at=req.expires_at,
    )


def _visible(stmt: Select, user: User) -> Select:
    """Everyone sees requests they sent or were asked to approve. Approvers also see their branch's requests
    (owners: every branch), so they can give the second approval."""
    stmt = stmt.join(DirectoryEntry, VerifyRequest.target_entry_id == DirectoryEntry.id).where(
        VerifyRequest.business_id == user.business_id)
    mine = or_(VerifyRequest.requested_by_id == user.id, DirectoryEntry.user_id == user.id)
    if user.role == Role.staff:
        return stmt.where(mine)
    branch_id = visible_branch_id(user)
    if branch_id is None:
        return stmt
    return stmt.where(or_(mine, VerifyRequest.branch_id == branch_id, VerifyRequest.branch_id.is_(None)))


def _get_visible(db: Session, verify_id: str, user: User) -> VerifyRequest:
    req = db.scalar(_visible(select(VerifyRequest).where(VerifyRequest.id == verify_id), user))
    if req is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "We couldn't find that Verify request.")
    if _expire_if_due(req):
        db.commit()
    return req


@router.post("/verify/requests", response_model=VerifyResponse, status_code=status.HTTP_201_CREATED)
def create_verify_request(body: VerifyCreateRequest, actor: Actor = Depends(current_actor),
                          db: Session = Depends(get_session)) -> VerifyResponse:
    user = actor.user
    entry = db.get(DirectoryEntry, body.target_person_id)
    if entry is None or entry.business_id != user.business_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "We couldn't find that person in your directory.")
    target = entry.user
    if target is None or not target.is_active or target.role not in APPROVER_ROLES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            f"{entry.name} can't approve requests in TriGuard. Call them back on the number saved "
                            "in the directory instead.")
    if target.id == user.id:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "You can't send a Verify request to yourself.")
    if body.call_id and db.scalar(scoped(select(Call.id).where(Call.id == body.call_id), Call, user)) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "We couldn't find that call.")

    now = datetime.now(UTC)
    req = VerifyRequest(
        business_id=user.business_id, branch_id=user.branch_id, requested_by_id=user.id, requested_by=user,
        target_entry_id=entry.id, target_entry=entry, request_type=body.request_type.strip(),
        amount_rand=body.amount, note=redact(body.note.strip()), call_id=body.call_id,
        requires_dual_approval=body.amount is not None and body.amount > user.business.payment_threshold_rand,
        created_at=now, expires_at=now + VERIFY_TTL,
    )
    db.add(req)
    amount = f" (R{body.amount:,.2f})" if body.amount is not None else ""
    audit(db, "VERIFY_REQUEST_SENT", f"{user.name} asked {entry.name} to verify: {req.request_type}{amount}",
          user=user)
    db.commit()
    # TODO: push a `verify_request` event to the approver's phone (FCM / WebSocket /events).
    return verify_response(req, user)


@router.get("/verify/requests", response_model=list[VerifyResponse])
def list_verify_requests(
    status_: VerifyStatus | None = Query(None, alias="status"),
    waiting_for_me: bool = Query(False, description="Only requests the signed-in user can approve now."),
    limit: int = Query(50, ge=1, le=200),
    actor: Actor = Depends(current_actor),
    db: Session = Depends(get_session),
) -> list[VerifyResponse]:
    now = datetime.now(UTC)
    stmt = _visible(select(VerifyRequest), actor.user)
    # Pending requests past their 5 minutes count as expired, even before they're marked.
    if status_ == VerifyStatus.pending or waiting_for_me:
        stmt = stmt.where(VerifyRequest.status == VerifyStatus.pending, VerifyRequest.expires_at > now)
    elif status_ == VerifyStatus.expired:
        stmt = stmt.where(or_(VerifyRequest.status == VerifyStatus.expired,
                              and_(VerifyRequest.status == VerifyStatus.pending, VerifyRequest.expires_at <= now)))
    elif status_:
        stmt = stmt.where(VerifyRequest.status == status_)
    reqs = list(db.scalars(stmt.order_by(VerifyRequest.created_at.desc()).limit(limit)))
    if any([_expire_if_due(r) for r in reqs]):
        db.commit()
    if waiting_for_me:
        reqs = [r for r in reqs if can_respond(r, actor.user)]
    return [verify_response(r, actor.user) for r in reqs]


@router.get("/verify/requests/{verify_id}", response_model=VerifyResponse)
def get_verify_request(verify_id: str, actor: Actor = Depends(current_actor),
                       db: Session = Depends(get_session)) -> VerifyResponse:
    """The app polls this on the waiting screen."""
    return verify_response(_get_visible(db, verify_id, actor.user), actor.user)


@router.post("/verify/{verify_id}/respond", response_model=VerifyResponse)
def respond_to_verify(verify_id: str, body: VerifyRespondRequest, actor: Actor = Depends(current_actor),
                      db: Session = Depends(get_session)) -> VerifyResponse:
    """Approve or reject (the app asks for a strong biometric first)."""
    user = actor.user
    req = _get_visible(db, verify_id, user)
    if req.status == VerifyStatus.expired:
        raise HTTPException(status.HTTP_409_CONFLICT, "This request has expired. Ask them to send a new one.")
    if req.status != VerifyStatus.pending:
        raise HTTPException(status.HTTP_409_CONFLICT, f"This request was already {req.status}.")
    if not can_respond(req, user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You can't approve or reject this request.")

    req.approvals.append(VerifyApproval(approver_id=user.id, approver=user, decision=body.decision))
    target_approved = any(a.approver_id == _target_user_id(req) and a.decision == "approve" for a in req.approvals)
    if body.decision == "reject":
        req.status = VerifyStatus.rejected
    elif target_approved and (not req.requires_dual_approval or _second_approval(req) is not None):
        req.status = VerifyStatus.approved
    if req.status != VerifyStatus.pending:
        req.decided_at = datetime.now(UTC)

    verb = "approved" if body.decision == "approve" else "rejected"
    audit(db, "VERIFY_APPROVED" if body.decision == "approve" else "VERIFY_REJECTED",
          f"{user.name} {verb} {req.requested_by.name}'s request: {req.request_type}", user=user,
          branch_id=req.branch_id)
    db.commit()
    # TODO: push a `verify_result` event to the requester's phone.
    return verify_response(req, user)
