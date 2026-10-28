"""Database tables.

Two groups:
- Community tables used by the PWA (number_reports, check_events). Their columns are unchanged from the original
  SQLite schema, so existing data/triguard.db files keep working.
- Business tables used by the Android app: businesses, branches, staff accounts, sign-in sessions, devices, the
  business directory, screened calls, Verify requests, scam reports and the audit log.

Call audio is never stored. Transcripts are cleared after TRANSCRIPT_RETENTION_DAYS (see app/db.py).
"""

import secrets
from datetime import UTC, datetime
from enum import Enum

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, UTCDateTime


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def utcnow() -> datetime:
    return datetime.now(UTC)


# --- Community tables (PWA) -------------------------------------------------------------------------------


class NumberReport(Base):
    __tablename__ = "number_reports"
    __table_args__ = (Index("idx_reports_number", "number"), {"sqlite_autoincrement": True})

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    number: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(Text)
    channel: Mapped[str] = mapped_column(Text)
    comment: Mapped[str | None] = mapped_column(Text)
    reporter_hash: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str] = mapped_column(Text, default="community", server_default="community")
    created_at: Mapped[str] = mapped_column(Text)  # ISO 8601 UTC string, as in the original schema


class CheckEvent(Base):
    __tablename__ = "check_events"
    __table_args__ = (Index("idx_checks_created", "created_at"), {"sqlite_autoincrement": True})

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    kind: Mapped[str] = mapped_column(Text)
    risk_level: Mapped[str] = mapped_column(Text)
    scam_type: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(Text)


# --- Business tables (Android app) ------------------------------------------------------------------------


class Role(str, Enum):
    owner = "owner"        # Owner / Admin: everything
    manager = "manager"    # their branch's alerts, approve Verify, directory (read), reports, audit
    finance = "finance"    # payment approvals, supplier bank-detail changes
    staff = "staff"        # receive screened calls, request checks, send Verify, report scam numbers


APPROVER_ROLES = {Role.owner, Role.manager, Role.finance}


class Business(Base):
    __tablename__ = "businesses"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("biz"))
    name: Mapped[str] = mapped_column(String(200))
    # The business's TriGuard screening number, once connected at the phone provider.
    screening_number: Mapped[str | None] = mapped_column(String(32))
    payment_threshold_rand: Mapped[float] = mapped_column(Float, default=5000)
    cooloff_hours: Mapped[int] = mapped_column(Integer, default=48)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    branches: Mapped[list["Branch"]] = relationship(back_populates="business")


class Branch(Base):
    __tablename__ = "branches"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("br"))
    business_id: Mapped[str] = mapped_column(ForeignKey("businesses.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))

    business: Mapped[Business] = relationship(back_populates="branches")


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("usr"))
    business_id: Mapped[str] = mapped_column(ForeignKey("businesses.id", ondelete="CASCADE"), index=True)
    # Empty = all branches (owners).
    branch_id: Mapped[str | None] = mapped_column(ForeignKey("branches.id", ondelete="SET NULL"))
    email: Mapped[str] = mapped_column(String(320), unique=True)  # stored lower-case
    name: Mapped[str] = mapped_column(String(200))
    role: Mapped[Role] = mapped_column(String(20))
    password_hash: Mapped[str] = mapped_column(String(300))
    totp_secret: Mapped[str | None] = mapped_column(String(64))
    # Last authenticator time-step used, so a code can't be replayed within its 30-second window.
    totp_last_step: Mapped[int] = mapped_column(Integer, default=0)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    business: Mapped[Business] = relationship()
    branch: Mapped[Branch | None] = relationship()


class LoginChallenge(Base):
    """Issued after a correct password; exchanged for tokens with the second step (the app's mfa_token)."""

    __tablename__ = "login_challenges"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("lc"))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    used_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("dev"))
    business_id: Mapped[str] = mapped_column(ForeignKey("businesses.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    fcm_token: Mapped[str | None] = mapped_column(String(4096))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    user: Mapped[User] = relationship()


class AuthSession(Base):
    """One signed-in app. Only SHA-256 hashes of the tokens are stored."""

    __tablename__ = "auth_sessions"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("ses"))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    device_id: Mapped[str | None] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    access_hash: Mapped[str] = mapped_column(String(64), unique=True)
    access_expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    refresh_hash: Mapped[str] = mapped_column(String(64), unique=True)
    # The refresh token before the last rotation. If it's used again, the token was copied: end the session.
    previous_refresh_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    refresh_expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    user: Mapped[User] = relationship()
    device: Mapped[Device | None] = relationship()


class DirectoryEntry(Base):
    __tablename__ = "directory_entries"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("dir"))
    business_id: Mapped[str] = mapped_column(ForeignKey("businesses.id", ondelete="CASCADE"), index=True)
    branch_id: Mapped[str | None] = mapped_column(ForeignKey("branches.id", ondelete="SET NULL"))
    # The person's TriGuard account, if they have one. Only linked people can approve Verify requests.
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    name: Mapped[str] = mapped_column(String(200))
    role_or_company: Mapped[str] = mapped_column(String(200), default="")
    category: Mapped[str] = mapped_column(String(20), default="staff")  # staff, supplier, bank, owner, executive
    aliases: Mapped[list[str]] = mapped_column(JSON, default=list)
    phone_numbers: Mapped[list[str]] = mapped_column(JSON, default=list)  # E.164
    backup_contact_name: Mapped[str | None] = mapped_column(String(200))
    backup_contact_phone: Mapped[str | None] = mapped_column(String(32))
    bank_reference: Mapped[str | None] = mapped_column(String(200))
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)

    branch: Mapped[Branch | None] = relationship()
    user: Mapped[User | None] = relationship()


class CallCategory(str, Enum):
    screened = "screened"
    silent_call = "silent_call"
    blocked_number = "blocked_number"
    direct_call = "direct_call"  # reached a staff phone without going through the TriGuard line


class Call(Base):
    """Result of screening one call. Written by the screening service; no audio, ever."""

    __tablename__ = "calls"
    __table_args__ = (Index("idx_calls_business_time", "business_id", "received_at"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("call"))
    business_id: Mapped[str] = mapped_column(ForeignKey("businesses.id", ondelete="CASCADE"))
    branch_id: Mapped[str | None] = mapped_column(ForeignKey("branches.id", ondelete="SET NULL"))
    received_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    caller_number: Mapped[str | None] = mapped_column(String(32))  # E.164; empty for hidden numbers
    claimed_id: Mapped[str | None] = mapped_column(String(200))
    directory_entry_id: Mapped[str | None] = mapped_column(ForeignKey("directory_entries.id", ondelete="SET NULL"))
    risk: Mapped[str] = mapped_column(String(10))  # high, medium, low - never "safe"
    category: Mapped[CallCategory] = mapped_column(String(20), default=CallCategory.screened)
    connect_to_staff: Mapped[bool] = mapped_column(Boolean, default=True)
    reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    action: Mapped[str] = mapped_column(Text, default="")
    require_verify: Mapped[bool] = mapped_column(Boolean, default=False)
    explanation: Mapped[str | None] = mapped_column(Text)
    voice_signal: Mapped[str | None] = mapped_column(String(40))  # "AI signs", "Unsure", "No strong AI signs"
    transcript: Mapped[str | None] = mapped_column(Text)

    branch: Mapped[Branch | None] = relationship()
    directory_entry: Mapped[DirectoryEntry | None] = relationship()


class VerifyStatus(str, Enum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    expired = "expired"


class VerifyRequest(Base):
    __tablename__ = "verify_requests"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("vr"))
    business_id: Mapped[str] = mapped_column(ForeignKey("businesses.id", ondelete="CASCADE"), index=True)
    branch_id: Mapped[str | None] = mapped_column(ForeignKey("branches.id", ondelete="SET NULL"))
    requested_by_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    target_entry_id: Mapped[str] = mapped_column(ForeignKey("directory_entries.id", ondelete="CASCADE"))
    request_type: Mapped[str] = mapped_column(String(100))
    amount_rand: Mapped[float | None] = mapped_column(Float)
    note: Mapped[str] = mapped_column(Text, default="")
    call_id: Mapped[str | None] = mapped_column(ForeignKey("calls.id", ondelete="SET NULL"))
    status: Mapped[VerifyStatus] = mapped_column(String(20), default=VerifyStatus.pending)
    requires_dual_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    requested_by: Mapped[User] = relationship()
    target_entry: Mapped[DirectoryEntry] = relationship()
    approvals: Mapped[list["VerifyApproval"]] = relationship(
        back_populates="request", order_by="VerifyApproval.created_at", cascade="all, delete-orphan"
    )


class VerifyApproval(Base):
    __tablename__ = "verify_approvals"
    __table_args__ = (UniqueConstraint("verify_id", "approver_id"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("va"))
    verify_id: Mapped[str] = mapped_column(ForeignKey("verify_requests.id", ondelete="CASCADE"))
    approver_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    decision: Mapped[str] = mapped_column(String(10))  # approve, reject
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    request: Mapped[VerifyRequest] = relationship(back_populates="approvals")
    approver: Mapped[User] = relationship()


class ScamReport(Base):
    """A number a business reported. Added to the shared TriGuard list only after review."""

    __tablename__ = "scam_reports"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("sr"))
    business_id: Mapped[str] = mapped_column(ForeignKey("businesses.id", ondelete="CASCADE"), index=True)
    reported_by_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    number: Mapped[str] = mapped_column(String(32), index=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    call_id: Mapped[str | None] = mapped_column(ForeignKey("calls.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(20), default="pending_review")  # pending_review, accepted, rejected
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class AuditEvent(Base):
    """Security log shown to owners and managers. No IP addresses or tokens."""

    __tablename__ = "audit_events"
    __table_args__ = (Index("idx_audit_business_time", "business_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("aud"))
    business_id: Mapped[str] = mapped_column(ForeignKey("businesses.id", ondelete="CASCADE"))
    branch_id: Mapped[str | None] = mapped_column(ForeignKey("branches.id", ondelete="SET NULL"))
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    actor_name: Mapped[str] = mapped_column(String(200), default="TriGuard")
    actor_role: Mapped[str | None] = mapped_column(String(20))
    event_type: Mapped[str] = mapped_column(String(50))
    summary: Mapped[str] = mapped_column(Text)
    details: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
