from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class RiskLevel(str, Enum):
    safe = "safe"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Indicator(BaseModel):
    """One reason behind a risk score, written so a non-technical user understands it."""

    code: str
    title: str
    detail: str
    weight: float = Field(ge=0, le=1, description="How much this indicator contributed (0-1).")
    source: Literal["ai_model", "acoustic", "rules", "llm", "reputation", "email_auth", "link"] = "rules"


class RiskAssessment(BaseModel):
    risk_level: RiskLevel
    risk_score: int = Field(ge=0, le=100)
    headline: str
    summary: str
    indicators: list[Indicator] = []
    advice: list[str] = []
    disclaimer: str = (
        "TriGuard gives risk indicators, not proof. When in doubt, end the conversation and "
        "contact the person or organisation on a number or channel you already trust."
    )


class VoiceModelResult(BaseModel):
    available: bool
    model_id: str | None = None
    synthetic_probability: float | None = None
    segments_analysed: int = 0
    note: str | None = None


class VoiceAnalysisResponse(RiskAssessment):
    kind: Literal["voice"] = "voice"
    duration_seconds: float
    model: VoiceModelResult
    acoustic_features: dict[str, float] = {}
    transcript: str | None = None
    transcript_risk: RiskAssessment | None = None


class MessageChannel(str, Enum):
    sms = "sms"
    email = "email"
    whatsapp = "whatsapp"  # only text the user chose to paste or share into TriGuard
    social = "social"
    other = "other"


class MessageAnalysisRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20_000)
    channel: MessageChannel = MessageChannel.other
    sender: str | None = Field(default=None, max_length=320, description="Phone number, email or name shown.")
    language: str = Field(default="en", description="Language for the explanation, e.g. en, af, zu, xh, st, tn.")


class ExtractedEntities(BaseModel):
    urls: list[str] = []
    phone_numbers: list[str] = []
    emails: list[str] = []
    amounts: list[str] = []


class MessageAnalysisResponse(RiskAssessment):
    kind: Literal["message", "email", "screenshot"] = "message"
    scam_type: str | None = None
    entities: ExtractedEntities = ExtractedEntities()
    links: list["LinkCheckResult"] = []
    ai_used: bool = False
    extracted_text: str | None = None


class LinkCheckRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


class LinkCheckResult(RiskAssessment):
    kind: Literal["link"] = "link"
    url: str
    domain: str | None = None
    reputation_checked: bool = False


class NumberReportCategory(str, Enum):
    impersonation_family = "impersonation_family"
    impersonation_bank = "impersonation_bank"
    impersonation_government = "impersonation_government"
    impersonation_employer = "impersonation_employer"
    ai_voice_clone = "ai_voice_clone"
    investment_scam = "investment_scam"
    job_scam = "job_scam"
    delivery_scam = "delivery_scam"
    sim_swap_otp = "sim_swap_otp"
    romance_scam = "romance_scam"
    spam_marketing = "spam_marketing"
    other = "other"


class NumberReportRequest(BaseModel):
    number: str = Field(min_length=3, max_length=32)
    category: NumberReportCategory
    comment: str | None = Field(default=None, max_length=500)
    channel: Literal["call", "sms", "whatsapp", "other"] = "call"
    reporter_id: str | None = Field(
        default=None, max_length=128, description="Anonymous per-install id so one device can't spam reports."
    )


class NumberReportResponse(BaseModel):
    number: str
    accepted: bool
    message: str


class CategoryCount(BaseModel):
    category: NumberReportCategory
    count: int


class NumberLookupResponse(RiskAssessment):
    model_config = ConfigDict(use_enum_values=False)

    kind: Literal["number"] = "number"
    number: str
    valid: bool
    region: str | None = None
    carrier: str | None = None
    line_type: str | None = None
    total_reports: int = 0
    categories: list[CategoryCount] = []
    last_reported_at: datetime | None = None
    recent_comments: list[str] = []


class ReportedNumber(BaseModel):
    number: str
    total_reports: int
    top_category: NumberReportCategory
    last_reported_at: datetime


MessageAnalysisResponse.model_rebuild()
