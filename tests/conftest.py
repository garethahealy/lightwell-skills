"""Session hooks. Failure output must not include Lightwell secrets."""

from __future__ import annotations

import pytest

from _redact import redact_report, secrets_from_environ


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport():
    outcome = yield
    secrets = secrets_from_environ()
    if secrets:
        redact_report(outcome.get_result(), secrets)
