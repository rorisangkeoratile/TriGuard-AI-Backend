"""Screened-call records: storing results from the screening service and showing them to each role."""

from collections.abc import Iterable

import phonenumbers
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.mobile_schemas import CallResponse, FlashMessage
from app.models import Call, CallCategory, DirectoryEntry, Role, User
from app.services.accounts import branch_label
from app.services.numbers import InvalidNumberError, normalise

BLOCKED_FLASH = {
    CallCategory.silent_call: ("Silent call blocked",
                               "The caller said nothing for 10 seconds, so TriGuard ended the call. Your phone did "
                               "not ring. Don't call this number back."),
    CallCategory.blocked_number: ("Scam number blocked",
                                  "This number is on the TriGuard scam list, so the call was ended before your "
                                  "phone rang."),
}


def mask_number(e164: str | None) -> str:
    """'+27 *** 0101': country code and last 4 digits only (what staff see)."""
    if not e164:
        return "Hidden number"
    try:
        parsed = phonenumbers.parse(e164)
    except phonenumbers.NumberParseException:
        return "*** " + e164[-4:]
    national = phonenumbers.national_significant_number(parsed)
    return f"+{parsed.country_code} *** {national[-4:]}"


def display_number(e164: str) -> str:
    try:
        return phonenumbers.format_number(phonenumbers.parse(e164), phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    except phonenumbers.NumberParseException:
        return e164


def normalise_numbers(numbers: Iterable[str]) -> list[str]:
    """E.164 for each number; raises InvalidNumberError with a friendly message."""
    result = []
    for number in numbers:
        if number.strip():
            e164, _ = normalise(number)
            if e164 not in result:
                result.append(e164)
    return result


def match_directory(db: Session, business_id: str, e164: str | None) -> DirectoryEntry | None:
    """The directory entry with this verified number. A match never unlocks a payment: caller ID can be spoofed."""
    if not e164:
        return None
    entries = db.scalars(select(DirectoryEntry).where(DirectoryEntry.business_id == business_id))
    return next((e for e in entries if e164 in (e.phone_numbers or [])), None)


def record_screened_call(db: Session, *, business_id: str, branch_id: str | None, caller_number: str | None,
                         risk: str, category: CallCategory, connect_to_staff: bool, reasons: list[str], action: str,
                         require_verify: bool, claimed_id: str | None = None, explanation: str | None = None,
                         voice_signal: str | None = None, transcript: str | None = None) -> Call:
    """Save the result of screening one call (for the screening service). The caller must commit."""
    if risk not in ("high", "medium", "low"):
        raise ValueError(f"Risk must be high, medium or low, not {risk!r}")
    e164 = None
    if caller_number:
        try:
            e164, _ = normalise(caller_number)
        except InvalidNumberError:
            e164 = caller_number[:32]
    entry = match_directory(db, business_id, e164)
    call = Call(business_id=business_id, branch_id=branch_id, caller_number=e164, claimed_id=claimed_id,
                directory_entry_id=entry.id if entry else None, risk=risk, category=category,
                connect_to_staff=connect_to_staff, reasons=reasons[:4], action=action,
                require_verify=require_verify, explanation=explanation, voice_signal=voice_signal,
                transcript=transcript)
    db.add(call)
    return call


def _flash(call: Call) -> FlashMessage | None:
    if call.category in BLOCKED_FLASH:
        title, message = BLOCKED_FLASH[CallCategory(call.category)]
        return FlashMessage(title=title, message=message, voice_signal=call.voice_signal)
    if call.voice_signal:
        return FlashMessage(voice_signal=call.voice_signal)
    return None


def call_response(call: Call, viewer: User) -> CallResponse:
    return CallResponse(
        call_id=call.id,
        received_at=call.received_at,
        risk=call.risk,
        category=call.category,
        connect_to_staff=call.connect_to_staff,
        caller_number_masked=mask_number(call.caller_number),
        caller_number=display_number(call.caller_number)
        if call.caller_number and viewer.role != Role.staff else None,
        claimed_id=call.claimed_id,
        in_directory=call.directory_entry_id is not None,
        directory_entry_id=call.directory_entry_id,
        reasons=call.reasons or [],
        action=call.action,
        require_verify=call.require_verify,
        explanation=call.explanation,
        transcript=call.transcript if viewer.role in (Role.owner, Role.manager) else None,
        flash=_flash(call),
        branch=branch_label(call.branch),
    )
