"""Threaded job helper with cancel-on-auth-failure for Collect phases."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import TypeVar

T = TypeVar("T")
R = TypeVar("R")


def map_threaded(
    items: list[T],
    fn: Callable[[int, T], R],
    *,
    max_workers: int,
    cancel_on: type[BaseException] | tuple[type[BaseException], ...] = (),
) -> list[R]:
    """Run ``fn(index, item)`` for each item; cancel outstanding on ``cancel_on``.

    Results are returned in the same order as ``items``. On ``cancel_on``,
    pending futures are cancelled and the exception is re-raised (caller handles).
    """
    if not items:
        return []
    results: list[R | None] = [None] * len(items)
    executor = ThreadPoolExecutor(max_workers=max_workers)
    try:
        futs: dict[Future[R], int] = {executor.submit(fn, i, item): i for i, item in enumerate(items)}
        try:
            for fut in as_completed(futs):
                results[futs[fut]] = fut.result()
        except cancel_on:
            for f in futs:
                f.cancel()
            raise
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
    return [r for r in results if r is not None]
