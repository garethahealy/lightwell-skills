"""Unit tests for download_http helpers (no network)."""

from __future__ import annotations

from lightwell_shared.download_http import HttpAuthError, header_value


def test_header_value_case() -> None:
    assert header_value({"ETag": '"abc"'}, "etag") == '"abc"'
    assert header_value({"etag": "x"}, "ETag") == "x"


def test_auth_error_message() -> None:
    err = HttpAuthError(403)
    assert "AUTH_FAILED" in str(err)
    assert "403" in str(err)
