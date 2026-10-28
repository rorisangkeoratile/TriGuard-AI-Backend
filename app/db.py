"""Community scam reports and anonymous check counts (PWA), plus clean-up of old data.

Only reported numbers and "a check happened, with this result" counters are stored - never user messages,
audio, screenshots or the numbers people look up. Tables are defined in app/models.py; the queries here are plain
SQL that runs on SQLite and PostgreSQL.
"""

import hashlib
import hmac
import logging
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from sqlalchemy import Connection, RowMapping, delete, or_, text, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import create_tables, get_engine
from app.models import AuditEvent, AuthSession, Call, LoginChallenge

log = logging.getLogger(__name__)

# Clearly fictional demo entries so the lookup screen has something to show during the hackathon.
DEMO_REPORTS = [
    ("+27710000001", "impersonation_family", "whatsapp", "'Hi Mom this is my new number' then asked for R2500"),
    ("+27710000001", "impersonation_family", "whatsapp", "Pretended to be my son, needed money for airtime"),
    ("+27710000001", "ai_voice_clone", "call", "Sounded exactly like my nephew, asked for an eWallet"),
    ("+27710000001", "impersonation_family", "sms", None),
    ("+27710000001", "impersonation_family", "whatsapp", "Same 'new number' story"),
    ("+27710000001", "ai_voice_clone", "call", None),
    ("+27820000002", "impersonation_bank", "call", "Said they're from the bank fraud dept and asked for my OTP"),
    ("+27820000002", "sim_swap_otp", "call", "Asked me to read the OTP they 'sent to verify' me"),
    ("+27820000002", "impersonation_bank", "call", None),
    ("+27610000003", "job_scam", "whatsapp", "Pay R350 'registration fee' for a work-from-home job"),
    ("+27610000003", "job_scam", "whatsapp", None),
    ("+27110000004", "spam_marketing", "call", "Insurance sales calls every day"),
]


@contextmanager
def connect() -> Iterator[Connection]:
    """A connection in a transaction, committed when the block ends."""
    with get_engine().begin() as conn:
        yield conn


def _rows(conn: Connection, sql: str, **params) -> list[RowMapping]:
    return list(conn.execute(text(sql), params).mappings())


# How long data is kept (POPIA s14: no longer than needed). Old reports also stop flagging recycled numbers.
REPORT_RETENTION_DAYS = 365
CHECK_EVENT_RETENTION_DAYS = 90
# Mobile app data. Transcripts are the most sensitive part of a call record, so they go first.
TRANSCRIPT_RETENTION_DAYS = 30
CALL_RETENTION_DAYS = 180
AUDIT_RETENTION_DAYS = 365


def purge_old_data() -> None:
    now = datetime.now(UTC)
    with connect() as conn:
        conn.execute(text("DELETE FROM number_reports WHERE source != 'demo' AND created_at < :before"),
                     {"before": (now - timedelta(days=REPORT_RETENTION_DAYS)).isoformat()})
        conn.execute(text("DELETE FROM check_events WHERE created_at < :before"),
                     {"before": (now - timedelta(days=CHECK_EVENT_RETENTION_DAYS)).isoformat()})
    with Session(get_engine()) as session:
        session.execute(update(Call).where(Call.received_at < now - timedelta(days=TRANSCRIPT_RETENTION_DAYS),
                                           Call.transcript.is_not(None)).values(transcript=None))
        session.execute(delete(Call).where(Call.received_at < now - timedelta(days=CALL_RETENTION_DAYS)))
        session.execute(delete(AuditEvent).where(AuditEvent.created_at < now - timedelta(days=AUDIT_RETENTION_DAYS)))
        session.execute(delete(LoginChallenge).where(LoginChallenge.expires_at < now))
        session.execute(delete(AuthSession).where(or_(AuthSession.refresh_expires_at < now,
                                                      AuthSession.revoked_at < now - timedelta(days=30))))
        session.commit()


def init_db() -> None:
    create_tables()
    if not get_settings().seed_demo_data:
        return
    with connect() as conn:
        if conn.execute(text("SELECT 1 FROM number_reports WHERE source = 'demo' LIMIT 1")).first():
            return
        now = datetime.now(UTC)
        conn.execute(
            text("INSERT INTO number_reports (number, category, channel, comment, reporter_hash, source, created_at)"
                 " VALUES (:number, :category, :channel, :comment, :reporter_hash, 'demo', :created_at)"),
            [{"number": n, "category": c, "channel": ch, "comment": cm, "reporter_hash": f"demo{i}",
              "created_at": (now - timedelta(days=i)).isoformat()}
             for i, (n, c, ch, cm) in enumerate(DEMO_REPORTS)],
        )


def _hash_key() -> bytes:
    """Secret key for reporter hashes, created once next to the database. Without a secret, a plain hash of an
    IP address could be reversed by trying all ~4 billion IPv4 addresses."""
    settings = get_settings()
    if settings.reporter_hash_secret:
        return settings.reporter_hash_secret.encode()
    path = settings.database_path.parent / ".reporter_key"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(secrets.token_hex(32))
    return path.read_text().strip().encode()


def hash_reporter(reporter_id: str | None, client_ip: str | None) -> str:
    raw = reporter_id or client_ip or "anonymous"
    return hmac.new(_hash_key(), raw.encode(), hashlib.sha256).hexdigest()[:32]


def add_report(number: str, category: str, channel: str, comment: str | None, reporter_hash: str) -> bool:
    """Store a report. Returns False if this reporter already reported this number in the last 24 hours."""
    since = (datetime.now(UTC) - timedelta(hours=24)).isoformat()
    with connect() as conn:
        duplicate = conn.execute(
            text("SELECT 1 FROM number_reports WHERE number = :number AND reporter_hash = :reporter_hash"
                 " AND created_at > :since"),
            {"number": number, "reporter_hash": reporter_hash, "since": since},
        ).first()
        if duplicate:
            return False
        conn.execute(
            text("INSERT INTO number_reports (number, category, channel, comment, reporter_hash, source, created_at)"
                 " VALUES (:number, :category, :channel, :comment, :reporter_hash, 'community', :created_at)"),
            {"number": number, "category": category, "channel": channel, "comment": comment,
             "reporter_hash": reporter_hash, "created_at": datetime.now(UTC).isoformat()},
        )
    return True


def get_reports(number: str) -> list[RowMapping]:
    with connect() as conn:
        return _rows(
            conn,
            "SELECT category, channel, comment, created_at FROM number_reports WHERE number = :number"
            " ORDER BY created_at DESC",
            number=number,
        )


def top_reported(limit: int = 20) -> list[RowMapping]:
    with connect() as conn:
        return _rows(
            conn,
            """
            SELECT number, COUNT(*) AS total, MAX(created_at) AS last_at,
                   (SELECT category FROM number_reports r2 WHERE r2.number = r.number
                    GROUP BY category ORDER BY COUNT(*) DESC LIMIT 1) AS top_category
            FROM number_reports r
            WHERE created_at > :since
            GROUP BY number ORDER BY total DESC, last_at DESC LIMIT :limit
            """,
            since=(datetime.now(UTC) - timedelta(days=30)).isoformat(), limit=limit,
        )


def record_check(kind: str, risk_level: str, scam_type: str | None = None) -> None:
    """Count a check for the Insights screen. Stores the result only, never what was checked."""
    try:
        with connect() as conn:
            conn.execute(
                text("INSERT INTO check_events (kind, risk_level, scam_type, created_at)"
                     " VALUES (:kind, :risk_level, :scam_type, :created_at)"),
                {"kind": kind, "risk_level": risk_level, "scam_type": scam_type,
                 "created_at": datetime.now(UTC).isoformat()},
            )
    except SQLAlchemyError:
        log.exception("Couldn't record check stats")  # stats must never break a check


def insight_counts() -> dict:
    now = datetime.now(UTC)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    week = (now - timedelta(days=7)).isoformat()
    month = (now - timedelta(days=30)).isoformat()
    with connect() as conn:
        def count(sql: str, since: str) -> int:
            return conn.execute(text(sql), {"since": since}).scalar_one()

        checks_today = count("SELECT COUNT(*) FROM check_events WHERE created_at >= :since", today)
        scams_today = count(
            "SELECT COUNT(*) FROM check_events WHERE created_at >= :since AND risk_level IN ('high', 'critical')",
            today,
        )
        reports_week = count("SELECT COUNT(*) FROM number_reports WHERE created_at >= :since", week)
        categories = _rows(
            conn,
            "SELECT category, COUNT(*) AS total FROM number_reports WHERE created_at >= :since"
            " GROUP BY category ORDER BY total DESC",
            since=month,
        )
    return {
        "checks_today": checks_today,
        "scams_detected_today": scams_today,
        "reports_this_week": reports_week,
        "report_categories": [(row["category"], row["total"]) for row in categories],
    }
