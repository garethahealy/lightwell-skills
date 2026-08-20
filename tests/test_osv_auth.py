"""Unit tests for summary_common OSV auth wrapping."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from lightwell_shared.download_http import HttpAuthError
from lightwell_shared.summary_common import OsvAuthError, fetch_osv_lines


def test_fetch_osv_auth_failed() -> None:
    with patch(
        "lightwell_shared.summary_common.fetch_osv_lines_for_bumps",
        side_effect=HttpAuthError(403),
    ):
        with pytest.raises(OsvAuthError):
            fetch_osv_lines([("g", "a", "1", "2")])
