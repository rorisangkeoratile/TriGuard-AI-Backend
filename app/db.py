"""Tiny store for community scam reports and anonymous check counts: SQLite locally, Postgres when
DATABASE_URL is set (the hosted deployment).

Only reported numbers and "a check happened, with this result" counters are stored - never user messages,
audio, screenshots or the numbers people look up.
"""

import hashlib
import hmac
import logging
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from app.config import get_settings

log = logging.getLogger(__name__)

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
CREATE TABLE IF NOT EXISTS check_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    scam_type TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_checks_created ON check_events(created_at);
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


class _Postgres:
    """Gives a psycopg connection the parts of the sqlite3 interface this module uses, so the queries below
    (plain SQL, dates stored as ISO text) run unchanged on both."""

    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql: str, params=()):
        return self._conn.execute(sql.replace("?", "%s"), params)

    def executemany(self, sql: str, rows) -> None:
        with self._conn.cursor() as cur:
            cur.executemany(sql.replace("?", "%s"), rows)

    def executescript(self, script: str) -> None:
        script = script.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")
        for statement in filter(str.strip, script.split(";")):
            self._conn.execute(statement)


@contextmanager
def connect():
    settings = get_settings()
    if settings.database_url:
        import psycopg
        from psycopg.rows import dict_row

        with psycopg.connect(settings.database_url, row_factory=dict_row, connect_timeout=10) as conn:
            yield _Postgres(conn)  # commits on success, rolls back on error
        return
    path = settings.database_path
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# How long data is kept (POPIA s14: no longer than needed). Old reports also stop flagging recycled numbers.
REPORT_RETENTION_DAYS = 365
CHECK_EVENT_RETENTION_DAYS = 90


def purge_old_data() -> None:
    now = datetime.now(UTC)
    with connect() as conn:
        conn.execute("DELETE FROM number_reports WHERE source != 'demo' AND created_at < ?",
                     ((now - timedelta(days=REPORT_RETENTION_DAYS)).isoformat(),))
        conn.execute("DELETE FROM check_events WHERE created_at < ?",
                     ((now - timedelta(days=CHECK_EVENT_RETENTION_DAYS)).isoformat(),))


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


def record_check(kind: str, risk_level: str, scam_type: str | None = None) -> None:
    """Count a check for the Insights screen. Stores the result only, never what was checked."""
    try:
        with connect() as conn:
            conn.execute(
                "INSERT INTO check_events (kind, risk_level, scam_type, created_at) VALUES (?, ?, ?, ?)",
                (kind, risk_level, scam_type, datetime.now(UTC).isoformat()),
            )
    except Exception:
        log.exception("Couldn't record check stats")  # stats must never break a check


def insight_counts() -> dict:
    now = datetime.now(UTC)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    week = (now - timedelta(days=7)).isoformat()
    month = (now - timedelta(days=30)).isoformat()
    with connect() as conn:
        checks_today = conn.execute(
            "SELECT COUNT(*) AS n FROM check_events WHERE created_at >= ?", (today,)).fetchone()["n"]
        scams_today = conn.execute(
            "SELECT COUNT(*) AS n FROM check_events WHERE created_at >= ? AND risk_level IN ('high', 'critical')",
            (today,),
        ).fetchone()["n"]
        reports_week = conn.execute(
            "SELECT COUNT(*) AS n FROM number_reports WHERE created_at >= ?", (week,)).fetchone()["n"]
        categories = conn.execute(
            "SELECT category, COUNT(*) AS total FROM number_reports WHERE created_at >= ?"
            " GROUP BY category ORDER BY total DESC",
            (month,),
        ).fetchall()
    return {
        "checks_today": checks_today,
        "scams_detected_today": scams_today,
        "reports_this_week": reports_week,
        "report_categories": [(row["category"], row["total"]) for row in categories],
    }
