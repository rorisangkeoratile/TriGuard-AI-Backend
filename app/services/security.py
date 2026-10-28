"""Passwords, sign-in tokens and authenticator (TOTP) codes for the mobile app.

- Passwords: scrypt (OWASP-recommended parameters), with a per-password salt.
- Tokens: 256-bit random strings. Only their SHA-256 hash is stored, so a database leak can't be used to sign in.
- Second step: 6-digit authenticator-app codes (RFC 6238). No SMS codes - SIM swaps can steal them.
"""

import base64
import hashlib
import hmac
import secrets
import time

import pyotp

# OWASP: scrypt N=2^15, r=8, p=3 (32 MiB). Stored with the hash so they can be raised later.
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**15, 8, 3
_SCRYPT_MAXMEM = 64 * 1024 * 1024
MIN_PASSWORD_LENGTH = 12
TOTP_ISSUER = "TriGuard AI"

# The most common passwords that still meet the length rule.
COMMON_PASSWORDS = {
    "password1234", "123456789012", "qwertyuiop12", "passwordpassword", "iloveyou1234", "1234567890123",
    "administrator", "letmein12345", "welcome12345", "triguard1234", "password123!", "qwerty123456",
}


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
                            maxmem=_SCRYPT_MAXMEM, dklen=32)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, digest = stored.split("$")
        expected = base64.b64decode(digest)
        actual = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                                maxmem=_SCRYPT_MAXMEM, dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


# Checked against when the email isn't registered, so a wrong email takes as long as a wrong password.
DUMMY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(16))


def password_problems(password: str, email: str) -> list[str]:
    """Plain-English reasons a new password isn't accepted (empty list = fine)."""
    problems = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"Use at least {MIN_PASSWORD_LENGTH} characters.")
    if password.lower() in COMMON_PASSWORDS or len(set(password)) < 4:
        problems.append("This password is too common or easy to guess.")
    if password.lower() == email.lower() or password.lower() == email.split("@")[0].lower():
        problems.append("Don't use your email address as your password.")
    return problems


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_setup_uri(secret: str, email: str) -> str:
    """otpauth:// link for authenticator apps (Google Authenticator, Microsoft Authenticator, Authy)."""
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=TOTP_ISSUER)


def check_totp(secret: str, code: str, last_step: int, now: float | None = None) -> int | None:
    """Returns the time-step the code belongs to, or None if it's wrong. Accepts the previous and next 30-second
    window for clock drift, but never a step at or before `last_step`, so each code works only once."""
    code = code.strip().replace(" ", "")
    if not (len(code) == 6 and code.isdigit()):
        return None
    totp = pyotp.TOTP(secret)
    current = int((time.time() if now is None else now) // totp.interval)
    for step in (current - 1, current, current + 1):
        if step > last_step and hmac.compare_digest(totp.at(step * totp.interval), code):
            return step
    return None
