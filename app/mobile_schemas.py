"""Request/response models for the TriGuard Android app (business call protection).

JSON keys are snake_case and follow section 7 of the app spec. Times are ISO 8601 in UTC.
Risk levels are only "high", "medium" or "low" - never "safe".
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

RiskLevel = Literal["high", "medium", "low"]
RoleName = Literal["owner", "manager", "finance", "staff"]


# --- Sign-in ----------------------------------------------------------------------------------------------


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=1024)


class LoginResponse(BaseModel):
    mfa_required: bool = True
    mfa_methods: list[str] = Field(description="Second steps this account can use. Passkeys are coming later.")
    mfa_token: str = Field(description="Send this back with the authenticator code. Valid for 5 minutes.")
    expires_in: int


class TotpRequest(BaseModel):
    mfa_token: str = Field(min_length=10, max_length=200)
    code: str = Field(min_length=6, max_length=10)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=10, max_length=200)


class MeResponse(BaseModel):
    id: str
    name: str
    email: str
    role: RoleName
    business: str
    business_id: str
    branch: str = Field(description="Branch name, or 'All Branches'.")
    branch_id: str | None
    permissions: list[str]


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int = Field(description="Seconds until the access token expires. Then call /auth/refresh.")
    user: MeResponse


class StatusResponse(BaseModel):
    status: str


# --- Devices ----------------------------------------------------------------------------------------------


class DeviceRegisterRequest(BaseModel):
    device_name: str = Field(min_length=1, max_length=200)
    fcm_token: str | None = Field(default=None, max_length=4096)
    integrity_token: str | None = Field(default=None, max_length=8192, description="Play Integrity (not checked yet).")


class DeviceRegisterResponse(BaseModel):
    device_id: str


class DeviceResponse(BaseModel):
    id: str
    device_name: str
    assigned_staff_name: str
    assigned_staff_id: str
    last_active: datetime
    is_current_device: bool
    status: Literal["Active", "Signed out"]


# --- Dashboard and calls ----------------------------------------------------------------------------------


class FlashMessage(BaseModel):
    title: str = "Temporary voice detection"
    message: str = "TriGuard checked the first 10 seconds of this caller's voice. The recording has been deleted."
    voice_signal: str | None = Field(description="'AI signs', 'Unsure' or 'No strong AI signs'.")
    ttl_seconds: int = 8


class CallResponse(BaseModel):
    call_id: str
    received_at: datetime
    risk: RiskLevel
    category: Literal["screened", "silent_call", "blocked_number", "direct_call"]
    connect_to_staff: bool
    caller_number_masked: str
    caller_number: str | None = Field(description="Full number. Only sent to owners, managers and finance.")
    claimed_id: str | None
    in_directory: bool
    directory_entry_id: str | None
    reasons: list[str]
    action: str
    require_verify: bool
    explanation: str | None
    transcript: str | None = Field(description="Only sent to owners and managers, while within retention.")
    flash: FlashMessage | None
    branch: str


class DashboardResponse(BaseModel):
    calls_screened_today: int
    high_risk_calls_today: int
    silent_calls_blocked_today: int
    scam_numbers_blocked_today: int
    verify_requests_pending: int
    system_status: str
    system_status_ok: bool
    recent_alerts: list[CallResponse]


# --- Guard 2: check a request -----------------------------------------------------------------------------


class RequestCheckRequest(BaseModel):
    call_id: str | None = Field(default=None, max_length=40)
    request_types: list[str] = Field(
        default=[], max_length=10,
        description="Chips the staff member tapped, e.g. 'Change bank details', 'Urgent payment', "
                    "'OTP / PIN / password', 'Vouchers or airtime', 'Remote access / install an app', "
                    "'Keep it secret', 'Other'.",
    )
    note: str = Field(default="", max_length=1000)


class RiskResult(BaseModel):
    risk: RiskLevel
    reasons: list[str]
    action: str
    require_verify: bool
    hard_stop: bool = Field(default=False, description="True for OTP/PIN/password requests: hang up.")
    explanation: str | None = None


# --- Guard 3: Verify --------------------------------------------------------------------------------------


class VerifyCreateRequest(BaseModel):
    target_person_id: str = Field(max_length=40, description="Directory entry id of the person to verify with.")
    request_type: str = Field(min_length=1, max_length=100)
    amount: float | None = Field(default=None, ge=0, le=1_000_000_000)
    note: str = Field(default="", max_length=1000)
    call_id: str | None = Field(default=None, max_length=40)


class VerifyRespondRequest(BaseModel):
    decision: Literal["approve", "reject"]


class ApprovalRecord(BaseModel):
    approver_id: str
    approver_name: str
    role: RoleName
    decision: Literal["approve", "reject"]
    timestamp: datetime


class VerifyResponse(BaseModel):
    verify_id: str
    status: Literal["pending", "approved", "rejected", "expired"]
    target_person_id: str
    target_person_name: str
    target_person_role: str
    requested_by_id: str
    requested_by_name: str
    request_type: str
    amount_rand: float | None
    note: str
    call_id: str | None
    branch: str
    requires_dual_approval: bool
    approvals: list[ApprovalRecord]
    waiting_for: list[str] = Field(description="Who still needs to approve, in plain words.")
    can_respond: bool = Field(description="Whether the signed-in user may approve or reject this request now.")
    created_at: datetime
    expires_at: datetime


# --- Directory --------------------------------------------------------------------------------------------

DirectoryCategory = Literal["staff", "supplier", "bank", "owner", "executive"]


class DirectoryEntryIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    role_or_company: str = Field(default="", max_length=200)
    category: DirectoryCategory = "staff"
    aliases: list[str] = Field(default=[], max_length=20)
    verified_phone_numbers: list[str] = Field(default=[], max_length=10)
    trusted_backup_contact_name: str | None = Field(default=None, max_length=200)
    trusted_backup_contact_phone: str | None = Field(default=None, max_length=32)
    bank_reference: str | None = Field(default=None, max_length=200)
    notes: str | None = Field(default=None, max_length=2000)
    branch_id: str | None = Field(default=None, max_length=40, description="Empty = all branches.")
    user_id: str | None = Field(default=None, max_length=40,
                                description="Link to this person's TriGuard account so they can approve Verify.")


class DirectoryEntryResponse(BaseModel):
    id: str
    name: str
    role_or_company: str
    category: DirectoryCategory
    aliases: list[str]
    verified_phone_numbers: list[str]
    trusted_backup_contact_name: str | None
    trusted_backup_contact_phone: str | None
    bank_reference: str | None = Field(description="Hidden from staff.")
    notes: str | None
    branch: str
    branch_id: str | None
    user_id: str | None
    can_approve_verify: bool
    voice_enrolled: bool = False
    voice_enrolled_date: str | None = None
    voiceprint_id: str | None = None


# --- Scam reports and audit -------------------------------------------------------------------------------


class ScamReportRequest(BaseModel):
    number: str = Field(min_length=3, max_length=32)
    reason: str = Field(default="", max_length=500)
    call_id: str | None = Field(default=None, max_length=40)


class ScamReportResponse(BaseModel):
    report_id: str | None
    number: str
    accepted: bool
    status: str
    message: str


class AuditEventResponse(BaseModel):
    id: str
    timestamp: datetime
    event_type: str
    summary: str
    actor_name: str
    actor_role: RoleName | None
    branch: str
    details: str
