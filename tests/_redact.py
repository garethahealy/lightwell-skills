"""Strip Lightwell secrets from pytest failure output.

Pytest prints function arguments on tracebacks. Scrub ``LIGHTWELL_TOKEN``, its
Basic encoding, ``LIGHTWELL_CLIENT_SECRET``, and access tokens the API client
has recorded, including saferepr's middle-ellipsis form.
"""

from __future__ import annotations

import base64
import os
import re
from typing import Any

from lightwell_shared.lightwell_api import noted_secrets

_MIN_SECRET_LEN = 24
_MARKER_LEN = 20
_TOKEN_BODY = r"(?:[A-Za-z0-9_./+=-]|\.\.\.)*"


def secrets_from_environ() -> list[str]:
    """Return credential strings worth redacting. Ignore short test placeholders."""
    secrets: list[str] = []
    token = os.environ.get("LIGHTWELL_TOKEN", "").strip()
    if len(token) >= _MIN_SECRET_LEN:
        secrets.append(token)
        user = os.environ.get("LIGHTWELL_USERNAME", "").strip()
        if user:
            basic = base64.b64encode(f"{user}:{token}".encode()).decode("ascii")
            secrets.append(basic)
    client_secret = os.environ.get("LIGHTWELL_CLIENT_SECRET", "").strip()
    if len(client_secret) >= _MIN_SECRET_LEN:
        secrets.append(client_secret)
    for value in noted_secrets():
        if value not in secrets:
            secrets.append(value)
    return secrets


def scrub_text(text: str, secrets: list[str]) -> str:
    """Replace each secret, including saferepr's middle-ellipsis form."""
    for secret in secrets:
        text = _scrub_one(text, secret)
    return text


def _scrub_one(text: str, secret: str) -> str:
    if len(secret) < _MIN_SECRET_LEN:
        return text
    if secret in text:
        text = text.replace(secret, "[redacted]")
    head = secret[:_MARKER_LEN]
    tail = secret[-_MARKER_LEN:]
    if head not in text and tail not in text:
        return text
    if head in text:
        text = re.sub(re.escape(head) + _TOKEN_BODY, "[redacted]", text)
    if tail in text:
        text = re.sub(_TOKEN_BODY + re.escape(tail), "[redacted]", text)
    return text


def redact_report(report: Any, secrets: list[str]) -> None:
    """Mutate a pytest report so its traceback text no longer contains secrets."""
    longrepr = report.longrepr
    if isinstance(longrepr, str):
        report.longrepr = scrub_text(longrepr, secrets)
    elif isinstance(longrepr, tuple) and len(longrepr) == 3:
        path, lineno, reason = longrepr
        report.longrepr = (path, lineno, scrub_text(str(reason), secrets))
    elif longrepr is not None:
        redact_longrepr(longrepr, secrets)
    sections = getattr(report, "sections", None)
    if sections:
        report.sections = [(name, scrub_text(content, secrets)) for name, content in sections]


def redact_longrepr(longrepr: Any, secrets: list[str]) -> None:
    """Mutate a pytest terminal repr in place."""
    seen: set[int] = set()
    tracebacks: list[Any] = []
    chain = getattr(longrepr, "chain", None)
    if chain:
        for traceback, crash, _description in chain:
            tracebacks.append(traceback)
            _scrub_message(crash, secrets)
    traceback = getattr(longrepr, "reprtraceback", None)
    if traceback is not None:
        tracebacks.append(traceback)
    _scrub_message(getattr(longrepr, "reprcrash", None), secrets)
    for traceback in tracebacks:
        if id(traceback) in seen:
            continue
        seen.add(id(traceback))
        extra = getattr(traceback, "extraline", None)
        if isinstance(extra, str):
            traceback.extraline = scrub_text(extra, secrets)
        for entry in getattr(traceback, "reprentries", ()):
            _redact_entry(entry, secrets)
    sections = getattr(longrepr, "sections", None)
    if sections:
        longrepr.sections = [(name, scrub_text(content, secrets), sep) for name, content, sep in sections]


def _scrub_message(node: Any, secrets: list[str]) -> None:
    if node is not None and hasattr(node, "message"):
        node.message = scrub_text(node.message, secrets)


def _redact_entry(entry: Any, secrets: list[str]) -> None:
    lines = getattr(entry, "lines", None)
    if lines is not None:
        entry.lines = [scrub_text(line, secrets) for line in lines]
    funcargs = getattr(entry, "reprfuncargs", None)
    args = getattr(funcargs, "args", None)
    if args is not None:
        funcargs.args = [(name, scrub_text(str(value), secrets)) for name, value in args]
    localsrepr = getattr(entry, "reprlocals", None)
    local_lines = getattr(localsrepr, "lines", None)
    if local_lines is not None:
        localsrepr.lines = [scrub_text(line, secrets) for line in local_lines]
    _scrub_message(getattr(entry, "reprfileloc", None), secrets)
