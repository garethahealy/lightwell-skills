"""Unit tests for http_pool coalescing (no network)."""

from __future__ import annotations

import base64
import threading

from lightwell_shared.http_pool import HttpsPool, basic_auth_header


def test_basic_auth_header() -> None:
    header = basic_auth_header("user", "tok")
    assert header.startswith("Basic ")
    decoded = base64.b64decode(header.split(" ", 1)[1]).decode("ascii")
    assert decoded == "user:tok"


def test_request_coalesces_same_url() -> None:
    pool = HttpsPool(max_per_host=2, timeout=5.0)
    calls = {"n": 0}
    lock = threading.Lock()

    def fake_uncached(url, *, headers, method):
        with lock:
            calls["n"] += 1
        threading.Event().wait(0.05)
        return 200, f"body-{url}", {"ETag": "x"}

    pool._request_uncached = fake_uncached  # type: ignore[method-assign]

    results: list[tuple] = []
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            results.append(pool.request("https://example.test/a", headers={}))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    assert len(results) == 12
    assert calls["n"] == 1, f"expected 1 coalesced fetch, got {calls['n']}"
    assert all(r[0] == 200 for r in results)
