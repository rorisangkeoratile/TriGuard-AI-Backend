"""Database connection shared by the whole backend.

SQLite (one local file, no setup) by default; set DATABASE_URL to a PostgreSQL URL to switch. Every query goes
through SQLAlchemy, so the same code runs on both.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from functools import lru_cache

from sqlalchemy import DateTime, Engine, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session
from sqlalchemy.types import TypeDecorator

from app.config import get_settings


class Base(DeclarativeBase):
    pass


class UTCDateTime(TypeDecorator):
    """Timezone-aware UTC datetimes on every database. SQLite has no timezone support and hands back naive
    values, which would break comparisons with datetime.now(UTC)."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("Store timezone-aware datetimes only")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


@lru_cache
def _engine_for(url: str) -> Engine:
    if url.startswith("sqlite"):
        engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 15})

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(conn, _):
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")  # readers don't block the writer

        return engine
    return create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=5)


def get_engine() -> Engine:
    settings = get_settings()
    if not settings.database_url:
        settings.database_path.parent.mkdir(parents=True, exist_ok=True)
    return _engine_for(settings.sqlalchemy_url)


def create_tables() -> None:
    from app import models  # noqa: F401 - registers the tables on Base.metadata

    Base.metadata.create_all(get_engine())


def get_session() -> Iterator[Session]:
    """FastAPI dependency: one session per request. Routes commit their own changes."""
    with Session(get_engine(), expire_on_commit=False) as session:
        yield session
