"""Failure tracebacks must not include Lightwell repository or API secrets."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from _paths import REPO_ROOT
from _redact import redact_longrepr, scrub_text, secrets_from_environ
from lightwell_shared.lightwell_api import clear_state


def _long_token() -> str:
    return "eyJ" + ("a" * 90) + "." + ("b" * 90) + "." + ("c" * 40)


def _ellipsize(text: str, maxsize: int = 240) -> str:
    if len(text) <= maxsize:
        return text
    head = max(0, (maxsize - 3) // 2)
    tail = max(0, maxsize - 3 - head)
    return text[:head] + "..." + text[len(text) - tail :]


def test_short_placeholder_is_not_a_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LIGHTWELL_USERNAME", "user")
    monkeypatch.setenv("LIGHTWELL_TOKEN", "fixture-token")
    monkeypatch.setenv("LIGHTWELL_CLIENT_ID", "client-id")
    monkeypatch.setenv("LIGHTWELL_CLIENT_SECRET", "client-secret")
    clear_state()
    assert secrets_from_environ() == []


def test_scrub_removes_full_and_truncated_token() -> None:
    secret = _long_token()
    shown = "\n".join(
        [
            f"token = {secret!r}",
            f"token = {_ellipsize(repr(secret))!s}",
            "still here",
        ]
    )
    redacted = scrub_text(shown, [secret])
    assert secret not in redacted
    assert secret[:20] not in redacted
    assert secret[-20:] not in redacted
    assert "[redacted]" in redacted
    assert "still here" in redacted


def test_exception_repr_hides_token(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = _long_token()
    monkeypatch.setenv("LIGHTWELL_USERNAME", "redact-user")
    monkeypatch.setenv("LIGHTWELL_TOKEN", secret)
    monkeypatch.setenv("LIGHTWELL_CLIENT_ID", "client-id")
    monkeypatch.setenv("LIGHTWELL_CLIENT_SECRET", "client-secret")
    clear_state()

    def callee(token: str) -> None:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError) as excinfo:
        callee(secret)

    formatted = excinfo.getrepr(funcargs=True, style="long")
    rendered_before = str(formatted)
    assert secret[:20] in rendered_before

    redact_longrepr(formatted, secrets_from_environ())
    rendered = str(formatted)
    assert secret not in rendered
    assert secret[:20] not in rendered
    assert secret[-20:] not in rendered
    assert "[redacted]" in rendered
    assert "boom" in rendered


def test_pytest_session_hides_token(tmp_path: Path) -> None:
    secret = _long_token()
    suite = tmp_path / "suite"
    suite.mkdir()
    (suite / "test_leak.py").write_text(
        "def callee(token: str) -> None:\n"
        "    raise RuntimeError('boom')\n"
        "\n"
        "def test_leak() -> None:\n"
        f"    callee({secret!r})\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["LIGHTWELL_USERNAME"] = "redact-user"
    env["LIGHTWELL_TOKEN"] = secret
    env["LIGHTWELL_CLIENT_ID"] = "client-id"
    env["LIGHTWELL_CLIENT_SECRET"] = "client-secret"
    scripts = REPO_ROOT / "plugins/lightwell/skills/lightwell-shared/scripts"
    env["PYTHONPATH"] = os.pathsep.join([str(REPO_ROOT / "tests"), str(scripts), env.get("PYTHONPATH", "")])
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(suite / "test_leak.py"),
            "-p",
            "conftest",
            "--override-ini",
            "addopts=",
            "--tb=long",
            "-q",
            "--noconftest",
        ],
        check=False,
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    output = proc.stdout + proc.stderr
    assert proc.returncode == 1
    assert secret not in output
    assert secret[:20] not in output
    assert secret[-20:] not in output
    assert "[redacted]" in output
    assert "boom" in output
