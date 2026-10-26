"""Tiny SQLite store for community scam reports. Only reported numbers are stored - never user messages or audio."""

import hashlib
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from app.config import get_settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS number_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    number TEXT NOT NULL,
    category TEXT NOT NULL,
    channel TEXT NOT NULL,
    comment TEXT,
    reporter_hash TEXT,
    source TEXT NOT NULL DEFAULT 'community',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_number ON number_reports(number);
"""

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
def connect():
    path = get_settings().database_path
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
        if get_settings().seed_demo_data:
            seeded = conn.execute("SELECT 1 FROM number_reports WHERE source = 'demo' LIMIT 1").fetchone()
            if not seeded:
                now = datetime.now(UTC)
                conn.executemany(
                    "INSERT INTO number_reports (number, category, channel, comment, reporter_hash, source, created_at)"
                    " VALUES (?, ?, ?, ?, ?, 'demo', ?)",
                    [(n, c, ch, cm, f"demo{i}", (now - timedelta(days=i)).isoformat())
                     for i, (n, c, ch, cm) in enumerate(DEMO_REPORTS)],
                )


def hash_reporter(reporter_id: str | None, client_ip: str | None) -> str:
    raw = reporter_id or client_ip or "anonymous"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def add_report(number: str, category: str, channel: str, comment: str | None, reporter_hash: str) -> bool:
    """Store a report. Returns False if this reporter already reported this number in the last 24 hours."""
    since = (datetime.now(UTC) - timedelta(hours=24)).isoformat()
    with connect() as conn:
        duplicate = conn.execute(
            "SELECT 1 FROM number_reports WHERE number = ? AND reporter_hash = ? AND created_at > ?",
            (number, reporter_hash, since),
        ).fetchone()
        if duplicate:
            return False
        conn.execute(
            "INSERT INTO number_reports (number, category, channel, comment, reporter_hash, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (number, category, channel, comment, reporter_hash, datetime.now(UTC).isoformat()),
        )
    return True


def get_reports(number: str) -> list[sqlite3.Row]:
    with connect() as conn:
        return conn.execute(
            "SELECT category, channel, comment, created_at FROM number_reports WHERE number = ?"
            " ORDER BY created_at DESC",
            (number,),
        ).fetchall()


def top_reported(limit: int = 20) -> list[sqlite3.Row]:
    with connect() as conn:
        return conn.execute(
            """
            SELECT number, COUNT(*) AS total, MAX(created_at) AS last_at,
                   (SELECT category FROM number_reports r2 WHERE r2.number = r.number
                    GROUP BY category ORDER BY COUNT(*) DESC LIMIT 1) AS top_category
            FROM number_reports r
            WHERE created_at > ?
            GROUP BY number ORDER BY total DESC, last_at DESC LIMIT ?
            """,
            ((datetime.now(UTC) - timedelta(days=30)).isoformat(), limit),
        ).fetchall()
