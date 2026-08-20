"""Unit tests for thread_jobs.map_threaded."""

from __future__ import annotations

import pytest

from lightwell_shared.thread_jobs import map_threaded


def test_map_threaded_preserves_order() -> None:
    def work(_idx: int, n: int) -> int:
        return n * 10

    assert map_threaded([1, 3, 4], work, max_workers=2) == [10, 30, 40]


def test_map_threaded_cancel_on_error() -> None:
    def work(_idx: int, n: int) -> int:
        if n == 2:
            raise RuntimeError("boom")
        return n * 10

    with pytest.raises(RuntimeError, match="boom"):
        map_threaded([1, 2, 3], work, max_workers=2, cancel_on=RuntimeError)
