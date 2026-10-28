"""Guard 2 for staff: what is the caller asking for, and what should the staff member do?

Rules from the app spec: never say "safe"; any request for money, bank-detail changes, OTPs/PINs/passwords, vouchers
or airtime always requires Verify, whatever the risk level; a known number never unlocks a payment by itself.
"""

import re

from app.mobile_schemas import RiskResult
from app.models import Call

# Request kind -> words that identify it in the app's chip labels or the staff member's note.
KEYWORDS = {
    "codes": r"\botp\b|\bpin\b|password|one[- ]time|verification code|\bcode\b",
    "bank_change": r"bank(ing)? detail|new (bank )?account|changed? (our |their )?bank|account number",
    "payment": r"payment|\bpay\b|\beft\b|transfer|invoice|deposit|\bmoney\b|\bcash\b|\br ?\d[\d ,.]*",
    "vouchers": r"voucher|airtime|gift ?card|e-?wallet|cash ?send",
    "remote_access": r"remote|install|anydesk|teamviewer|download|\bapp\b|till software",
    "secrecy": r"secret|don'?t tell|keep it quiet|between us|confidential",
    "urgency": r"urgent|right now|immediately|asap|today|hurry|quick",
}

REASONS = {
    "codes": "The caller asked for a code, PIN or password.",
    "bank_change": "The caller wants to change bank details.",
    "payment": "The caller is asking for a payment.",
    "vouchers": "The caller is asking for vouchers, airtime or e-wallet money.",
    "remote_access": "The caller wants you to install something or give remote access.",
    "secrecy": "The caller asked you to keep this secret.",
    "urgency": "The caller is rushing you.",
}

MONEY = {"bank_change", "payment", "vouchers"}
CALLBACK = "Tap Verify, or hang up and call back on the number saved in the directory."
LEVELS = {"low": 0, "medium": 1, "high": 2}


def detect(request_types: list[str], note: str) -> set[str]:
    text = " ".join(request_types + [note]).lower()
    return {kind for kind, pattern in KEYWORDS.items() if re.search(pattern, text)}


def check_request(request_types: list[str], note: str = "", call: Call | None = None) -> RiskResult:
    kinds = detect(request_types, note)
    reasons = [REASONS[k] for k in REASONS if k in kinds]
    money = kinds & MONEY

    if "codes" in kinds:
        result = RiskResult(
            risk="high", reasons=reasons, hard_stop=True, require_verify=True,
            action="Never share codes or passwords with a caller. Hang up.",
            explanation="Banks, suppliers and IT support never need your codes. Anyone asking for one over the "
                        "phone is trying to get into an account.",
        )
    elif "remote_access" in kinds:
        result = RiskResult(
            risk="high", reasons=reasons, require_verify=True,
            action="Don't install anything or give remote access. Hang up and call your IT contact on a number "
                   "you already have.",
            explanation="Remote access lets a scammer control the till or computer and steal card or banking "
                        "details.",
        )
    elif money:
        pressure = kinds & {"secrecy", "urgency"}
        # A plain payment request can be routine; bank changes, vouchers or pressure almost never are.
        high = bool(money & {"bank_change", "vouchers"}) or bool(pressure) or len(money) > 1
        result = RiskResult(
            risk="high" if high else "medium", reasons=reasons, require_verify=True,
            action=f"Don't pay or change anything yet. {CALLBACK}",
            explanation="Scammers pretend to be owners and suppliers to get urgent payments. A familiar voice or "
                        "number isn't enough - caller ID can be faked and voices can be cloned.",
        )
    elif "secrecy" in kinds:
        result = RiskResult(
            risk="medium", reasons=reasons, require_verify=False,
            action=f"Be careful: real managers and suppliers don't ask for secrets. {CALLBACK}",
        )
    else:
        result = RiskResult(
            risk="low", reasons=reasons or ["The caller hasn't asked for money, codes or bank changes."],
            require_verify=False, action="Carry on, but verify any request for money or codes.",
        )

    if call is not None and LEVELS[call.risk] > LEVELS[result.risk]:
        result.risk = call.risk
        result.reasons.append(f"TriGuard rated this call {call.risk} risk when it was screened.")
        if call.require_verify and not result.require_verify:
            result.require_verify = True
            result.action = f"Don't act on this call. {CALLBACK}"
    result.reasons = result.reasons[:4]
    return result
