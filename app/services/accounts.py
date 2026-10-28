"""Staff accounts: permissions per role, branch visibility and the audit log."""

from sqlalchemy.orm import Session

from app.mobile_schemas import MeResponse
from app.models import AuditEvent, Branch, Role, User

ALL_BRANCHES = "All Branches"

PERMISSIONS: dict[Role, list[str]] = {
    Role.owner: ["all"],
    Role.manager: ["receive_calls", "check_requests", "send_verify", "report_scams", "view_alerts",
                   "approve_verify", "view_directory", "suggest_directory", "view_reports", "view_audit",
                   "view_transcripts"],
    Role.finance: ["receive_calls", "check_requests", "send_verify", "report_scams", "view_directory",
                   "approve_verify", "approve_payments", "bank_changes"],
    Role.staff: ["receive_calls", "check_requests", "send_verify", "report_scams", "view_directory"],
}


def branch_label(branch: Branch | None) -> str:
    return branch.name if branch else ALL_BRANCHES


def visible_branch_id(user: User) -> str | None:
    """The one branch this user may see, or None for every branch (owners, and people not tied to a branch)."""
    return None if user.role == Role.owner else user.branch_id


def me_response(user: User) -> MeResponse:
    return MeResponse(
        id=user.id, name=user.name, email=user.email, role=user.role, business=user.business.name,
        business_id=user.business_id, branch=branch_label(user.branch), branch_id=user.branch_id,
        permissions=PERMISSIONS[Role(user.role)],
    )


def audit(db: Session, event_type: str, summary: str, *, user: User | None = None, business_id: str | None = None,
          branch_id: str | None = None, details: str = "") -> None:
    """Add a security event to the audit log (committed with the caller's transaction). Never put tokens,
    passwords, codes or full phone numbers in here."""
    db.add(AuditEvent(
        business_id=business_id or user.business_id,
        branch_id=branch_id if branch_id is not None else (user.branch_id if user else None),
        actor_id=user.id if user else None,
        actor_name=user.name if user else "TriGuard",
        actor_role=user.role if user else None,
        event_type=event_type,
        summary=summary,
        details=details,
    ))
