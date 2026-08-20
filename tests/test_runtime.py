"""Tests for interpreter pin and PATH preflight."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from lightwell_shared.runtime import MIN_PYTHON, missing_binaries, preflight, require_python


def test_require_python_accepts_current() -> None:
    require_python()


def test_require_python_rejects_old() -> None:
    with patch("lightwell_shared.runtime.sys") as mock_sys:
        mock_sys.version_info = (3, 12, 0)
        mock_sys.stderr = __import__("sys").stderr
        with pytest.raises(SystemExit) as exc:
            require_python()
        assert exc.value.code == 2


def test_min_python_is_3_14() -> None:
    assert MIN_PYTHON == (3, 14)


def test_missing_binaries_definitely_absent() -> None:
    assert "definitely-not-a-real-binary-xyz" in missing_binaries("definitely-not-a-real-binary-xyz")


def test_preflight_jq_when_requested() -> None:
    missing = preflight(jq=True, gh=True)
    assert isinstance(missing, list)
