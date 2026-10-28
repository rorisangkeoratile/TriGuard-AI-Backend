"""Android app API: sign-in, devices, dashboard, calls, request checks, Verify, directory, scam reports, audit."""

import time

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.orm import Session

PASSWORD = "correct horse battery"


@pytest.fixture(scope="module")
def monkeypatch_module():
    mp = pytest.MonkeyPatch()
    yield mp
    mp.undo()


@pytest.fixture(scope="module")
def client(tmp_path_factory, monkeypatch_module):
    monkeypatch_module.setenv("DATABASE_PATH", str(tmp_path_factory.mktemp("db") / "mobile.db"))
    monkeypatch_module.setenv("DATABASE_URL", "")
    for key in ("VOICE_MODEL_ENABLED", "TRANSCRIPTION_ENABLED", "LLM_ENABLED", "MMS_ENABLED"):
        monkeypatch_module.setenv(key, "false")
    from app.config import get_settings

    get_settings.cache_clear()
    from app.main import app

    with TestClient(app) as c:
        yield c
    get_settings.cache_clear()


@pytest.fixture(scope="module")
def shop(client):
    """A business with two branches: owner, finance and staff in Cape Town, a manager in Durban."""
    from app.cli import add_sample_data, add_user, create_owner
    from app.database import get_engine
    from app.models import Role

    with Session(get_engine(), expire_on_commit=False) as db:
        owner, owner_secret = create_owner(db, business_name="SuperSave", branches=["Cape Town Main", "Durban"],
                                           name="Dev Naidoo", email="owner@supersave.test", password=PASSWORD)
        business = owner.business
        add_sample_data(db, business)
        people = {"owner": (owner, owner_secret)}
        for key, name, role, branch in [("finance", "Sipho Khumalo", Role.finance, "Cape Town Main"),
                                        ("staff", "Thabo Molefe", Role.staff, "Cape Town Main"),
                                        ("durban", "Priya Govender", Role.manager, "Durban")]:
            people[key] = add_user(db, business=business, name=name, email=f"{key}@supersave.test",
                                   password=PASSWORD, role=role, branch_name=branch)
        db.commit()
    return {key: {"id": u.id, "email": u.email, "secret": s} for key, (u, s) in people.items()}


def _allow_new_code(user_id: str) -> None:
    """Each authenticator code works once; tests sign in many times within 30 seconds."""
    from app.database import get_engine
    from app.models import User

    with Session(get_engine()) as db:
        db.execute(update(User).where(User.id == user_id).values(totp_last_step=0))
        db.commit()


def sign_in(client, person: dict) -> dict:
    _allow_new_code(person["id"])
    first = client.post("/auth/login", json={"email": person["email"], "password": PASSWORD})
    assert first.status_code == 200, first.text
    assert first.json()["mfa_methods"] == ["totp"]
    second = client.post("/auth/mfa/totp", json={"mfa_token": first.json()["mfa_token"],
                                                 "code": pyotp.TOTP(person["secret"]).now()})
    assert second.status_code == 200, second.text
    return second.json()


def auth(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def test_sign_in_returns_tokens_and_profile(client, shop):
    tokens = sign_in(client, shop["staff"])
    assert tokens["token_type"] == "bearer"
    assert tokens["user"]["role"] == "staff"
    assert tokens["user"]["branch"] == "Cape Town Main"
    me = client.get("/me", headers=auth(tokens)).json()
    assert me["email"] == "staff@supersave.test"
    assert "send_verify" in me["permissions"]


def test_wrong_password_and_unknown_email_look_the_same(client, shop):
    wrong = client.post("/auth/login", json={"email": "owner@supersave.test", "password": "nope"})
    unknown = client.post("/auth/login", json={"email": "nobody@supersave.test", "password": "nope"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_code_cannot_be_reused(client, shop):
    person = shop["finance"]
    _allow_new_code(person["id"])
    code = pyotp.TOTP(person["secret"]).now()
    for expected in (200, 401):
        token = client.post("/auth/login", json={"email": person["email"], "password": PASSWORD}).json()
        assert client.post("/auth/mfa/totp", json={"mfa_token": token["mfa_token"], "code": code}).status_code \
            == expected


def test_lockout_after_five_wrong_passwords(client, shop):
    from app.cli import add_user
    from app.database import get_engine
    from app.models import Business, Role

    with Session(get_engine()) as db:
        add_user(db, business=db.scalar(select(Business)), name="Lock Test", email="lock@supersave.test",
                 password=PASSWORD, role=Role.staff)
        db.commit()
    for _ in range(5):
        assert client.post("/auth/login", json={"email": "lock@supersave.test", "password": "x"}).status_code == 401
    locked = client.post("/auth/login", json={"email": "lock@supersave.test", "password": PASSWORD})
    assert locked.status_code == 429
    assert "Too many attempts" in locked.json()["detail"]


def test_requests_without_a_valid_token_get_401(client):
    assert client.get("/dashboard").status_code == 401
    assert client.get("/dashboard", headers={"Authorization": "Bearer made-up"}).status_code == 401


def test_refresh_rotates_and_reuse_ends_the_session(client, shop):
    tokens = sign_in(client, shop["staff"])
    renewed = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert renewed.status_code == 200
    assert client.get("/me", headers=auth(renewed.json())).status_code == 200
    # Using the old refresh token again looks like theft: the whole session ends.
    assert client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401
    assert client.get("/me", headers=auth(renewed.json())).status_code == 401


def test_logout(client, shop):
    tokens = sign_in(client, shop["staff"])
    assert client.post("/auth/logout", headers=auth(tokens)).json() == {"status": "signed_out"}
    assert client.get("/me", headers=auth(tokens)).status_code == 401


def test_owner_signs_out_a_stolen_device(client, shop):
    staff = sign_in(client, shop["staff"])
    device_id = client.post("/devices/register", headers=auth(staff),
                            json={"device_name": "Till 2 phone", "fcm_token": "fcm-abc"}).json()["device_id"]
    assert client.get("/devices", headers=auth(staff)).status_code == 403  # staff can't manage devices

    owner = sign_in(client, shop["owner"])
    devices = client.get("/devices", headers=auth(owner)).json()
    assert any(d["id"] == device_id and d["assigned_staff_name"] == "Thabo Molefe" for d in devices)
    revoked = client.post(f"/devices/{device_id}/revoke", headers=auth(owner)).json()
    assert revoked["status"] == "Signed out"
    assert client.get("/dashboard", headers=auth(staff)).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": staff["refresh_token"]}).status_code == 401


def test_dashboard_counts_todays_calls(client, shop):
    data = client.get("/dashboard", headers=auth(sign_in(client, shop["owner"]))).json()
    assert data["calls_screened_today"] == 4
    assert data["high_risk_calls_today"] == 1
    assert data["silent_calls_blocked_today"] == 1
    assert data["scam_numbers_blocked_today"] == 1
    assert data["system_status"] == "Screening is ON"
    assert {a["risk"] for a in data["recent_alerts"]} <= {"high", "medium"}


def test_calls_hide_numbers_and_transcripts_from_staff(client, shop):
    staff_calls = client.get("/calls", headers=auth(sign_in(client, shop["staff"]))).json()
    owner_calls = client.get("/calls", params={"risk": "high"},
                             headers=auth(sign_in(client, shop["owner"]))).json()
    cloned = next(c for c in staff_calls if c["claimed_id"] == "owner")
    assert cloned["caller_number"] is None and cloned["transcript"] is None
    assert cloned["caller_number_masked"] == "+27 *** 0000"
    assert cloned["flash"]["voice_signal"] == "AI signs"
    owner_view = next(c for c in owner_calls if c["call_id"] == cloned["call_id"])
    assert owner_view["caller_number"] == "+27 82 555 0000"
    assert "R20,000" in owner_view["transcript"]
    assert all(c["risk"] == "high" for c in owner_calls)
    assert all(c["risk"] in {"high", "medium", "low"} for c in staff_calls)


def test_other_branches_calls_are_hidden(client, shop):
    durban = client.get("/calls", headers=auth(sign_in(client, shop["durban"]))).json()
    assert durban == []


@pytest.mark.parametrize("types, note, risk, verify, hard_stop", [
    (["OTP / PIN / password"], "", "high", True, True),
    (["Change bank details"], "", "high", True, False),
    (["Urgent payment"], "", "high", True, False),
    (["Vouchers or airtime"], "", "high", True, False),
    (["Remote access / install an app"], "", "high", True, False),
    ([], "He wants me to pay the invoice", "medium", True, False),
    (["Other"], "Asking when the delivery arrives", "low", False, False),
])
def test_request_check(client, shop, types, note, risk, verify, hard_stop):
    result = client.post("/request-check", headers=auth(sign_in(client, shop["staff"])),
                         json={"request_types": types, "note": note})
    assert result.status_code == 200
    body = result.json()
    assert (body["risk"], body["require_verify"], body["hard_stop"]) == (risk, verify, hard_stop)
    assert "safe" not in result.text.lower()


def test_request_check_takes_the_call_risk_into_account(client, shop):
    staff = sign_in(client, shop["staff"])
    call = next(c for c in client.get("/calls", headers=auth(staff)).json() if c["claimed_id"] == "owner")
    body = client.post("/request-check", headers=auth(staff),
                       json={"request_types": ["Other"], "call_id": call["call_id"]}).json()
    assert body["risk"] == "high" and body["require_verify"] is True


def _directory_id(client, tokens, name):
    return next(e["id"] for e in client.get("/directory", headers=auth(tokens)).json() if e["name"] == name)


def test_verify_owner_approves(client, shop):
    staff = sign_in(client, shop["staff"])
    owner_entry = _directory_id(client, staff, "Dev Naidoo")
    created = client.post("/verify/requests", headers=auth(staff), json={
        "target_person_id": owner_entry, "request_type": "Urgent payment", "amount": 2000, "note": "Caller asked"})
    assert created.status_code == 201, created.text
    req = created.json()
    assert req["status"] == "pending" and req["requires_dual_approval"] is False
    assert req["waiting_for"] == ["Dev Naidoo"]

    # Nobody approves their own request, and only the named person can approve a normal one.
    assert client.post(f"/verify/{req['verify_id']}/respond", headers=auth(staff),
                       json={"decision": "approve"}).status_code == 403
    finance = sign_in(client, shop["finance"])
    assert client.post(f"/verify/{req['verify_id']}/respond", headers=auth(finance),
                       json={"decision": "approve"}).status_code == 403

    owner = sign_in(client, shop["owner"])
    inbox = client.get("/verify/requests", params={"waiting_for_me": True}, headers=auth(owner)).json()
    assert [r["verify_id"] for r in inbox] == [req["verify_id"]]
    done = client.post(f"/verify/{req['verify_id']}/respond", headers=auth(owner), json={"decision": "approve"})
    assert done.json()["status"] == "approved"
    assert client.get(f"/verify/requests/{req['verify_id']}", headers=auth(staff)).json()["status"] == "approved"


def test_verify_large_payment_needs_two_people(client, shop):
    staff = sign_in(client, shop["staff"])
    req = client.post("/verify/requests", headers=auth(staff), json={
        "target_person_id": _directory_id(client, staff, "Dev Naidoo"), "request_type": "Payment",
        "amount": 20000}).json()
    assert req["requires_dual_approval"] is True
    owner, finance = sign_in(client, shop["owner"]), sign_in(client, shop["finance"])
    after_owner = client.post(f"/verify/{req['verify_id']}/respond", headers=auth(owner),
                              json={"decision": "approve"}).json()
    assert after_owner["status"] == "pending"
    assert after_owner["waiting_for"] == ["a second approver (owner, manager or finance)"]
    after_finance = client.post(f"/verify/{req['verify_id']}/respond", headers=auth(finance),
                                json={"decision": "approve"}).json()
    assert after_finance["status"] == "approved"
    assert [a["approver_name"] for a in after_finance["approvals"]] == ["Dev Naidoo", "Sipho Khumalo"]


def test_verify_reject_and_expiry(client, shop):
    from app.database import get_engine
    from app.models import VerifyRequest

    staff, owner = sign_in(client, shop["staff"]), sign_in(client, shop["owner"])
    target = _directory_id(client, staff, "Dev Naidoo")
    rejected = client.post("/verify/requests", headers=auth(staff),
                           json={"target_person_id": target, "request_type": "Bank change"}).json()
    assert client.post(f"/verify/{rejected['verify_id']}/respond", headers=auth(owner),
                       json={"decision": "reject"}).json()["status"] == "rejected"

    stale = client.post("/verify/requests", headers=auth(staff),
                        json={"target_person_id": target, "request_type": "Vouchers"}).json()
    from datetime import UTC, datetime, timedelta
    with Session(get_engine()) as db:
        db.execute(update(VerifyRequest).where(VerifyRequest.id == stale["verify_id"])
                   .values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
        db.commit()
    assert client.get(f"/verify/requests/{stale['verify_id']}", headers=auth(staff)).json()["status"] == "expired"
    assert client.post(f"/verify/{stale['verify_id']}/respond", headers=auth(owner),
                       json={"decision": "approve"}).status_code == 409


def test_verify_needs_someone_who_can_approve(client, shop):
    staff = sign_in(client, shop["staff"])
    supplier = _directory_id(client, staff, "FreshFarm Logistics SA")
    resp = client.post("/verify/requests", headers=auth(staff),
                       json={"target_person_id": supplier, "request_type": "Bank change"})
    assert resp.status_code == 422
    assert "call them back" in resp.json()["detail"].lower()


def test_directory_owner_edits_staff_reads(client, shop):
    owner, staff = sign_in(client, shop["owner"]), sign_in(client, shop["staff"])
    entry = {"name": "CleanCo", "role_or_company": "Cleaning supplier", "category": "supplier",
             "verified_phone_numbers": ["021 555 9999"], "bank_reference": "ABSA ...1111"}
    assert client.post("/directory", headers=auth(staff), json=entry).status_code == 403
    created = client.post("/directory", headers=auth(owner), json=entry)
    assert created.status_code == 201
    assert created.json()["verified_phone_numbers"] == ["+27215559999"]

    seen_by_staff = next(e for e in client.get("/directory", params={"q": "clean"}, headers=auth(staff)).json())
    assert seen_by_staff["bank_reference"] is None
    entry_id = created.json()["id"]
    updated = client.put(f"/directory/{entry_id}", headers=auth(owner), json={**entry, "aliases": ["Cleaners"]})
    assert updated.json()["aliases"] == ["Cleaners"]
    assert client.delete(f"/directory/{entry_id}", headers=auth(owner)).status_code == 204
    assert client.post("/directory", headers=auth(owner),
                       json={**entry, "verified_phone_numbers": ["12"]}).status_code == 422


def test_scam_report_once_per_day(client, shop):
    staff = sign_in(client, shop["staff"])
    first = client.post("/scam-reports", headers=auth(staff), json={"number": "071 555 8888", "reason": "Fake bank"})
    assert first.status_code == 201 and first.json()["accepted"] is True
    assert first.json()["number"] == "+27 *** 8888"
    again = client.post("/scam-reports", headers=auth(staff), json={"number": "+27715558888", "reason": "Again"})
    assert again.json()["accepted"] is False


def test_audit_log_for_owner_only(client, shop):
    assert client.get("/audit", headers=auth(sign_in(client, shop["staff"]))).status_code == 403
    events = client.get("/audit", headers=auth(sign_in(client, shop["owner"]))).json()
    types = {e["event_type"] for e in events}
    assert {"SIGN_IN", "SIGN_IN_FAILED", "DEVICE_SIGNED_OUT", "VERIFY_APPROVED", "ACCESS_DENIED"} <= types
    assert PASSWORD not in str(events)
    assert "+27715558888" not in str(events)  # reported numbers are masked


def test_check_totp_window():
    from app.services.security import check_totp

    secret = pyotp.random_base32()
    now = time.time()
    code = pyotp.TOTP(secret).at(now)
    step = check_totp(secret, code, 0, now=now)
    assert step is not None
    assert check_totp(secret, code, step, now=now) is None  # replay
    assert check_totp(secret, "000000" if code != "000000" else "111111", 0, now=now) is None
    assert check_totp(secret, code, 0, now=now + 300) is None  # far too old
