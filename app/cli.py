"""Set up businesses and staff accounts for the Android app.

    python -m app.cli create-owner --business "SuperSave" --branch "Cape Town Main" --name "Dev Naidoo" \
        --email owner@supersave.co.za --sample-data
    python -m app.cli add-user --email thabo@supersave.co.za --name "Thabo Molefe" --role staff \
        --branch "Cape Town Main"
    python -m app.cli reset-second-step --email thabo@supersave.co.za

Each command asks for the password (it is never shown or stored in plain text) and prints the authenticator setup
key for that person's phone.
"""

import argparse
import getpass
import sys
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import create_tables, get_engine
from app.models import APPROVER_ROLES, Branch, Business, CallCategory, DirectoryEntry, Role, User
from app.services.accounts import audit
from app.services.calls import normalise_numbers, record_screened_call
from app.services.numbers import InvalidNumberError
from app.services.security import hash_password, new_totp_secret, password_problems, totp_setup_uri


class SetupError(Exception):
    pass


def create_owner(db: Session, *, business_name: str, branches: list[str], name: str, email: str,
                 password: str) -> tuple[User, str]:
    business = Business(name=business_name.strip())
    db.add(business)
    for branch in branches or ["Main"]:
        db.add(Branch(business=business, name=branch.strip()))
    db.flush()
    return add_user(db, business=business, name=name, email=email, password=password, role=Role.owner)


def add_user(db: Session, *, business: Business, name: str, email: str, password: str, role: Role,
             branch_name: str | None = None, phone: str | None = None) -> tuple[User, str]:
    """Create a staff account. Owners, managers and finance also get a directory entry, so staff can send them
    Verify requests. Returns the user and their authenticator secret."""
    email = email.strip().lower()
    if db.scalar(select(User.id).where(User.email == email)):
        raise SetupError(f"There is already an account for {email}.")
    if problems := password_problems(password, email):
        raise SetupError(" ".join(problems))
    branch = None
    if branch_name:
        branch = db.scalar(select(Branch).where(Branch.business_id == business.id, Branch.name == branch_name))
        if branch is None:
            names = ", ".join(b.name for b in business.branches)
            raise SetupError(f"No branch called {branch_name!r}. Branches: {names}")
    try:
        phone_numbers = normalise_numbers([phone or ""])
    except InvalidNumberError as exc:
        raise SetupError(str(exc)) from exc
    secret = new_totp_secret()
    user = User(business=business, branch=branch, email=email, name=name.strip(), role=role,
                password_hash=hash_password(password), totp_secret=secret)
    db.add(user)
    if role in APPROVER_ROLES:
        db.add(DirectoryEntry(
            business_id=business.id, branch=branch, user=user, name=user.name,
            role_or_company={Role.owner: "Business Owner", Role.manager: "Manager", Role.finance: "Finance"}[role],
            category="owner" if role == Role.owner else "staff", phone_numbers=phone_numbers,
        ))
    db.flush()
    audit(db, "ACCOUNT_CREATED", f"Account created for {user.name} ({role.value})", business_id=business.id,
          branch_id=user.branch_id)
    return user, secret


def reset_second_step(db: Session, email: str) -> tuple[User, str]:
    user = db.scalar(select(User).where(User.email == email.strip().lower()))
    if user is None:
        raise SetupError(f"No account for {email}.")
    user.totp_secret = new_totp_secret()
    user.totp_last_step = 0
    audit(db, "SECOND_STEP_RESET", f"{user.name}'s authenticator was reset by an admin", user=user)
    return user, user.totp_secret


def add_sample_data(db: Session, business: Business) -> None:
    """Fictional suppliers and today's screened calls (the demo scenarios), so every screen has something to
    show. The phone numbers use reserved, unassigned ranges."""
    business.screening_number = "+27215550000"
    branch = business.branches[0] if business.branches else None
    for name, company, numbers, backup, bank in [
        ("FreshFarm Logistics SA", "Bakery & Fresh Produce Supplier", ["+27 21 555 1234"],
         ("Jacques Steyn (Key Account Director)", "+27 82 555 8765"), "Nedbank ...8812"),
        ("MediSupply Distribution", "Pharmaceuticals Supplier", ["+27 11 555 9000"],
         ("Brenda Khanyile", "+27 83 555 2211"), "Standard Bank ...4490"),
    ]:
        db.add(DirectoryEntry(business_id=business.id, branch=branch, name=name, role_or_company=company,
                              category="supplier", phone_numbers=normalise_numbers(numbers),
                              backup_contact_name=backup[0], backup_contact_phone=normalise_numbers([backup[1]])[0],
                              bank_reference=bank))
    db.flush()
    now = datetime.now(UTC)
    samples = [
        dict(caller_number="+27 82 555 0000", risk="high", category=CallCategory.screened, connect_to_staff=True,
             claimed_id="owner", voice_signal="AI signs", require_verify=True,
             reasons=["This number is not in your business directory.",
                      "The voice shows strong signs of being AI-generated.",
                      "The caller says they are someone in your directory, but the voice does not match theirs.",
                      "The caller mentioned urgency, a payment, changed bank details, secrecy."],
             action="Do not act on this call. Tap Verify, or hang up and call back on the directory number.",
             explanation="Someone claiming to be the owner is asking for an urgent payment, and the voice doesn't "
                         "match - verify before doing anything.",
             transcript="Hi, it's Mr Naidoo. I need you to pay R20,000 into a new account right now. Don't tell "
                        "anyone, I'll explain later."),
        dict(caller_number="+27 71 555 4321", risk="high", category=CallCategory.silent_call,
             connect_to_staff=False, require_verify=False,
             reasons=["The caller said nothing for 10 seconds."],
             action="Your phone did not ring. Don't call this number back."),
        dict(caller_number="+27 61 555 7777", risk="high", category=CallCategory.blocked_number,
             connect_to_staff=False, require_verify=False,
             reasons=["This number is on the TriGuard scam list."],
             action="The call was ended before your phone rang."),
        dict(caller_number="+27 21 555 1234", risk="low", category=CallCategory.screened, connect_to_staff=True,
             claimed_id="FreshFarm Logistics SA", voice_signal="No strong AI signs", require_verify=False,
             reasons=["This number is in your business directory.", "The caller asked about a delivery time."],
             action="Carry on, but verify any request for money or codes.",
             transcript="Morning, it's FreshFarm, just checking the bread delivery is still fine for 10 o'clock."),
    ]
    for i, sample in enumerate(samples):
        call = record_screened_call(db, business_id=business.id, branch_id=branch.id if branch else None, **sample)
        call.received_at = now - timedelta(minutes=10 * (len(samples) - i))


# --- Command line -----------------------------------------------------------------------------------------


def _ask_password(email: str) -> str:
    while True:
        password = getpass.getpass(f"New password for {email} (at least 12 characters, typing is hidden): ")
        if problems := password_problems(password, email):
            print("  " + " ".join(problems))
            continue
        if getpass.getpass("Type it again: ") == password:
            return password
        print("  The passwords didn't match.")


def _print_second_step(user: User, secret: str) -> None:
    print(f"\n{user.name} <{user.email}> - {Role(user.role).value}")
    print("Set up the second step on their phone: open Google Authenticator, Microsoft Authenticator or Authy,")
    print("tap +, choose 'Enter a setup key', and enter:")
    print(f"    Account: {user.email}\n    Key:     {secret}\n    Type:    Time based")
    print(f"(Or turn this link into a QR code: {totp_setup_uri(secret, user.email)} )")
    print("This key is shown once. Anyone who has it can make sign-in codes, so don't save or share it.\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    owner = sub.add_parser("create-owner", help="Create a business, its branches and the owner's account.")
    owner.add_argument("--business", required=True)
    owner.add_argument("--branch", action="append", default=[], help="Repeat for each branch.")
    owner.add_argument("--name", required=True)
    owner.add_argument("--email", required=True)
    owner.add_argument("--sample-data", action="store_true", help="Add fictional suppliers and screened calls.")

    user = sub.add_parser("add-user", help="Add a staff account to a business.")
    user.add_argument("--email", required=True)
    user.add_argument("--name", required=True)
    user.add_argument("--role", required=True, choices=[r.value for r in Role])
    user.add_argument("--branch", help="Branch name. Leave out for all branches.")
    user.add_argument("--phone", help="Their verified phone number (for the directory).")
    user.add_argument("--business-id", help="Needed only when there is more than one business.")

    reset = sub.add_parser("reset-second-step", help="New authenticator key for someone who lost their phone.")
    reset.add_argument("--email", required=True)

    args = parser.parse_args(argv)
    create_tables()
    with Session(get_engine(), expire_on_commit=False) as db:
        try:
            if args.command == "create-owner":
                created, secret = create_owner(db, business_name=args.business, branches=args.branch,
                                               name=args.name, email=args.email,
                                               password=_ask_password(args.email))
                if args.sample_data:
                    add_sample_data(db, created.business)
            elif args.command == "add-user":
                businesses = list(db.scalars(select(Business)))
                if args.business_id:
                    businesses = [b for b in businesses if b.id == args.business_id]
                if len(businesses) != 1:
                    ids = ", ".join(f"{b.id} ({b.name})" for b in businesses) or "none - run create-owner first"
                    raise SetupError(f"Choose a business with --business-id. Businesses: {ids}")
                created, secret = add_user(db, business=businesses[0], name=args.name, email=args.email,
                                           password=_ask_password(args.email), role=Role(args.role),
                                           branch_name=args.branch, phone=args.phone)
            else:
                created, secret = reset_second_step(db, args.email)
            db.commit()
        except SetupError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
    _print_second_step(created, secret)
    return 0


if __name__ == "__main__":
    sys.exit(main())
