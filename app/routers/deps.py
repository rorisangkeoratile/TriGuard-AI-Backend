"""Shared FastAPI dependencies for the mobile app: who is signed in, and what their role allows."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_session
from app.models import AuthSession, Role, User
from app.services.accounts import audit
from app.services.security import hash_token

bearer = HTTPBearer(auto_error=False, description="Access token from /auth/mfa/totp or /auth/refresh.")
LAST_SEEN_RESOLUTION = timedelta(minutes=5)

SIGNED_OUT = HTTPException(
    status.HTTP_401_UNAUTHORIZED, "Please sign in again.", headers={"WWW-Authenticate": "Bearer"}
)


@dataclass
class Actor:
    """The signed-in staff member and their session."""

    user: User
    session: AuthSession


def current_actor(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_session),
) -> Actor:
    """Any 401 tells the app to wipe its session and go back to sign-in (e.g. after a remote device sign-out)."""
    if credentials is None:
        raise SIGNED_OUT
    session = db.scalar(select(AuthSession).where(AuthSession.access_hash == hash_token(credentials.credentials)))
    now = datetime.now(UTC)
    if (session is None or session.revoked_at is not None or session.access_expires_at <= now
            or not session.user.is_active or (session.device is not None and session.device.revoked_at is not None)):
        raise SIGNED_OUT
    if session.device is not None and now - session.device.last_seen_at > LAST_SEEN_RESOLUTION:
        session.device.last_seen_at = now
        db.commit()
    return Actor(session.user, session)


def require_roles(*roles: Role) -> Callable[..., Actor]:
    def check(actor: Actor = Depends(current_actor), db: Session = Depends(get_session)) -> Actor:
        if actor.user.role not in roles:
            audit(db, "ACCESS_DENIED", f"{actor.user.name} tried to open something their role can't use",
                  user=actor.user)
            db.commit()
            raise HTTPException(status.HTTP_403_FORBIDDEN, "You don't have access to this.")
        return actor

    return check
