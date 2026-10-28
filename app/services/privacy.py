"""POPIA data minimisation: mask personal identifiers before text leaves the server or gets stored.

Scam checks don't need anyone's full ID, card or account number - only that one is being asked for.
Names can't be reliably detected, so free text is still treated as personal information.
"""

import logging
import re

# Order matters: longer, more specific patterns first.
_PATTERNS = [
    # Card numbers written in groups of four: 4111 1111 1111 1111.
    (re.compile(r"\b\d{4}([ -])\d{4}\1\d{4}\1\d{1,7}\b"), "[card number]"),
    # 13-19 digits in a row: SA ID numbers (13) and card numbers.
    (re.compile(r"(?<![\d+])\d{13,19}(?!\d)"), "[ID or card number]"),
    (re.compile(r"(?<![\d+])\d{11,12}(?!\d)"), "[account number]"),
    # Email: keep the domain - a fake domain is a scam signal - and hide the person's mailbox name.
    (re.compile(r"\b[\w.+-]+@([\w-]+(?:\.[\w-]+)+)\b"), r"***@\1"),
    # SA phone numbers: keep the start (network/area) and last 2 digits, which is enough to discuss them.
    (re.compile(r"(?<![\w+])(?:(\+27)\s?|0)(\d{2})[\s-]?\d{3}[\s-]?\d{2}(\d{2})\b"),
     lambda m: f"{'+27 ' if m[1] else '0'}{m[2]} *** **{m[3]}"),
    # Remaining 9-10 digit runs are bank account numbers (SA accounts are usually 9-11 digits).
    (re.compile(r"(?<![\d+])\d{9,10}(?!\d)"), "[account number]"),
]


def redact(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class AccessLogFilter(logging.Filter):
    """Uvicorn logs every request as (client, method, path, version, status). Drop the client IP and the
    query string, so looked-up phone numbers never end up in log files."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple) and len(record.args) == 5:
            _, method, path, version, status = record.args
            record.args = ("-", method, str(path).split("?", 1)[0], version, status)
        return True
