"""Mobile app sign-in (email + password, then an authenticator code), sessions, /me and devices."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_session
from app.mobile_schemas import (
    DeviceRegisterRequest,
    DeviceRegisterResponse,
    DeviceResponse,
    LoginRequest,
    LoginResponse,
    MeResponse,
    RefreshRequest,
    StatusResponse,
    TokenResponse,
    TotpRequest,
)
from app.models import AuthSession, Device, LoginChallenge, Role, User
from app.routers.deps import SIGNED_OUT, Actor, current_actor, require_roles
from app.services.accounts import audit, me_response
from app.services.security import DUMMY_PASSWORD_HASH, check_totp, hash_token, new_token, verify_password

router = APIRouter(tags=["mobile: sign-in"])
devices_router = APIRouter(prefix="/devices", tags=["mobile: devices"])

MAX_FAILED_LOGINS = 5
LOCKOUT = timedelta(minutes=15)
CHALLENGE_TTL = timedelta(minutes=5)
MAX_CODE_ATTEMPTS = 5

WRONG_PASSWORD = HTTPException(status.HTTP_401_UNAUTHORIZED, "Email or password is incorrect.")
LOCKED = HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts, try again in a few minutes.")
CHALLENGE_GONE = HTTPException(status.HTTP_401_UNAUTHORIZED,
                               "Your sign-in timed out. Please enter your password again.")


def _failed_attempt(db: Session, user: User, what: str) -> None:
    user.failed_logins += 1
    if user.failed_logins >= MAX_FAILED_LOGINS:
        user.failed_logins = 0
        user.locked_until = datetime.now(UTC) + LOCKOUT
        audit(db, "ACCOUNT_LOCKED", f"{user.name}'s sign-in was locked for 15 minutes after {MAX_FAILED_LOGINS} "
              f"wrong attempts", user=user)
    audit(db, "SIGN_IN_FAILED", f"Failed sign-in for {user.name} ({what})", user=user)
    db.commit()


def _is_locked(user: User) -> bool:
    return user.locked_until is not None and user.locked_until > datetime.now(UTC)


def _issue_tokens(session: AuthSession) -> tuple[str, str]:
    settings = get_settings()
    now = datetime.now(UTC)
    access, refresh = new_token(), new_token()
    session.access_hash = hash_token(access)
    session.access_expires_at = now + timedelta(minutes=settings.access_token_minutes)
    session.refresh_hash = hash_token(refresh)
    session.refresh_expires_at = now + timedelta(days=settings.refresh_token_days)
    return access, refresh


def _token_response(session: AuthSession, access: str, refresh: str) -> TokenResponse:
    return TokenResponse(access_token=access, refresh_token=refresh,
                         expires_in=get_settings().access_token_minutes * 60, user=me_response(session.user))


@router.post("/auth/login", response_model=LoginResponse)
def login(body: LoginRequest, db: Session = Depends(get_session)) -> LoginResponse:
    """Step 1: email + password. Returns an mfa_token to use with the authenticator code."""
    user = db.scalar(select(User).where(User.email == body.email.strip().lower()))
    if user is None:
        verify_password(body.password, DUMMY_PASSWORD_HASH)  # same timing as a real account
        raise WRONG_PASSWORD
    if _is_locked(user):
        raise LOCKED
    if not verify_password(body.password, user.password_hash) or not user.is_active:
        _failed_attempt(db, user, "wrong password")
        raise WRONG_PASSWORD
    if not user.totp_secret:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "Two-step sign-in isn't set up for this account yet. Ask your business admin.")

    token = new_token()
    db.add(LoginChallenge(user_id=user.id, token_hash=hash_token(token),
                          expires_at=datetime.now(UTC) + CHALLENGE_TTL))
    db.commit()
    return LoginResponse(mfa_methods=["totp"], mfa_token=token, expires_in=int(CHALLENGE_TTL.total_seconds()))


@router.post("/auth/mfa/totp", response_model=TokenResponse)
def verify_totp(body: TotpRequest, db: Session = Depends(get_session)) -> TokenResponse:
    """Step 2: the 6-digit code from the authenticator app. Returns the access and refresh tokens."""
    challenge = db.scalar(select(LoginChallenge).where(LoginChallenge.token_hash == hash_token(body.mfa_token)))
    now = datetime.now(UTC)
    if challenge is None or challenge.used_at is not None or challenge.expires_at <= now:
        raise CHALLENGE_GONE
    user = db.get(User, challenge.user_id)
    if user is None or not user.is_active or not user.totp_secret:
        raise CHALLENGE_GONE
    if _is_locked(user):
        raise LOCKED

    step = check_totp(user.totp_secret, body.code, user.totp_last_step)
    if step is None:
        challenge.attempts += 1
        if challenge.attempts >= MAX_CODE_ATTEMPTS:
            challenge.used_at = now
        _failed_attempt(db, user, "wrong authenticator code")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "That code isn't right. Check your authenticator app and try again.")

    challenge.used_at = now
    user.totp_last_step = step
    user.failed_logins = 0
    user.locked_until = None
    session = AuthSession(user_id=user.id, user=user)
    access, refresh = _issue_tokens(session)
    db.add(session)
    audit(db, "SIGN_IN", f"{user.name} signed in", user=user)
    db.commit()
    return _token_response(session, access, refresh)


@router.post("/auth/refresh", response_model=TokenResponse)
def refresh(body: RefreshRequest, db: Session = Depends(get_session)) -> TokenResponse:
    """Swap a refresh token for new tokens. Each refresh token works once."""
    token_hash = hash_token(body.refresh_token)
    now = datetime.now(UTC)
    session = db.scalar(select(AuthSession).where(AuthSession.refresh_hash == token_hash))
    if session is None:
        # An old refresh token used again means someone copied it: end that session for safety.
        reused = db.scalar(select(AuthSession).where(AuthSession.previous_refresh_hash == token_hash))
        if reused is not None and reused.revoked_at is None:
            reused.revoked_at = now
            audit(db, "SESSION_REVOKED", f"{reused.user.name} was signed out because an old sign-in token was "
                  "reused", user=reused.user)
            db.commit()
        raise SIGNED_OUT
    if (session.revoked_at is not None or session.refresh_expires_at <= now or not session.user.is_active
            or (session.device is not None and session.device.revoked_at is not None)):
        raise SIGNED_OUT

    session.previous_refresh_hash = token_hash
    access, refresh_token = _issue_tokens(session)
    db.commit()
    return _token_response(session, access, refresh_token)


@router.post("/auth/logout", response_model=StatusResponse)
def logout(actor: Actor = Depends(current_actor), db: Session = Depends(get_session)) -> StatusResponse:
    actor.session.revoked_at = datetime.now(UTC)
    audit(db, "SIGN_OUT", f"{actor.user.name} signed out", user=actor.user)
    db.commit()
    return StatusResponse(status="signed_out")


@router.get("/me", response_model=MeResponse, tags=["mobile: sign-in"])
def me(actor: Actor = Depends(current_actor)) -> MeResponse:
    return me_response(actor.user)


# --- Devices ----------------------------------------------------------------------------------------------


def _device_response(device: Device, actor: Actor) -> DeviceResponse:
    return DeviceResponse(
        id=device.id, device_name=device.name, assigned_staff_name=device.user.name,
        assigned_staff_id=device.user_id, last_active=device.last_seen_at,
        is_current_device=device.id == actor.session.device_id,
        status="Signed out" if device.revoked_at else "Active",
    )


@devices_router.post("/register", response_model=DeviceRegisterResponse)
def register_device(body: DeviceRegisterRequest, actor: Actor = Depends(current_actor),
                    db: Session = Depends(get_session)) -> DeviceRegisterResponse:
    """Register this phone to the signed-in staff member (after the first sign-in on it)."""
    # TODO: verify body.integrity_token with the Play Integrity API before trusting the device.
    device = actor.session.device
    if device is None:
        device = Device(business_id=actor.user.business_id, user_id=actor.user.id, name=body.device_name.strip())
        db.add(device)
        db.flush()
        actor.session.device_id = device.id
        audit(db, "DEVICE_REGISTERED", f"{actor.user.name} registered {device.name}", user=actor.user)
    device.name = body.device_name.strip()
    device.fcm_token = body.fcm_token
    db.commit()
    return DeviceRegisterResponse(device_id=device.id)


@devices_router.get("", response_model=list[DeviceResponse])
def list_devices(actor: Actor = Depends(require_roles(Role.owner)),
                 db: Session = Depends(get_session)) -> list[DeviceResponse]:
    devices = db.scalars(select(Device).where(Device.business_id == actor.user.business_id)
                         .order_by(Device.revoked_at.is_not(None), Device.last_seen_at.desc()))
    return [_device_response(d, actor) for d in devices]


@devices_router.post("/{device_id}/revoke", response_model=DeviceResponse)
def revoke_device(device_id: str, actor: Actor = Depends(require_roles(Role.owner)),
                  db: Session = Depends(get_session)) -> DeviceResponse:
    """Sign out a lost or stolen phone. Its next request gets 401 and the app returns to sign-in."""
    device = db.get(Device, device_id)
    if device is None or device.business_id != actor.user.business_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "We couldn't find that device.")
    now = datetime.now(UTC)
    if device.revoked_at is None:
        device.revoked_at = now
        db.execute(update(AuthSession).where(AuthSession.device_id == device.id, AuthSession.revoked_at.is_(None))
                   .values(revoked_at=now))
        audit(db, "DEVICE_SIGNED_OUT", f"{actor.user.name} signed out {device.name} ({device.user.name})",
              user=actor.user, branch_id=device.user.branch_id)
        db.commit()
    return _device_response(device, actor)
