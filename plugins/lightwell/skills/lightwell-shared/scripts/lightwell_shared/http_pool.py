"""Pooled HTTPS client (stdlib) for Lightwell metadata fetches.

Keeps keep-alive connections per host across ThreadPool workers, follows
redirects (packages.redhat.com → CDN), and coalesces in-flight GETs for the
same URL so parallel workers share one round-trip.
"""

from __future__ import annotations

import base64
import http.client
import os
import ssl
import threading
from urllib.parse import urljoin, urlparse


class HttpFetchError(Exception):
    pass


class _HostPool:
    """Keep-alive HTTPSConnection pool for one host:port."""

    def __init__(self, host: str, port: int, *, maxsize: int, timeout: float) -> None:
        self.host = host
        self.port = port
        self.maxsize = maxsize
        self.timeout = timeout
        self._ctx = ssl.create_default_context()
        self._lock = threading.Lock()
        self._idle: list[http.client.HTTPSConnection] = []
        self._created = 0

    def acquire(self) -> http.client.HTTPSConnection:
        with self._lock:
            while self._idle:
                conn = self._idle.pop()
                # Drop dead sockets
                try:
                    if conn.sock is None:
                        conn.connect()
                    return conn
                except OSError:
                    try:
                        conn.close()
                    except OSError:
                        pass
                    self._created = max(0, self._created - 1)
            if self._created < self.maxsize:
                self._created += 1
                create = True
            else:
                create = False
        if create:
            return http.client.HTTPSConnection(
                self.host,
                self.port,
                timeout=self.timeout,
                context=self._ctx,
            )
        # Oversubscribe briefly rather than block Collect workers
        return http.client.HTTPSConnection(
            self.host,
            self.port,
            timeout=self.timeout,
            context=self._ctx,
        )

    def release(self, conn: http.client.HTTPSConnection, *, discard: bool) -> None:
        if discard:
            try:
                conn.close()
            except OSError:
                pass
            with self._lock:
                self._created = max(0, self._created - 1)
            return
        with self._lock:
            if len(self._idle) < self.maxsize:
                self._idle.append(conn)
                return
            self._created = max(0, self._created - 1)
        try:
            conn.close()
        except OSError:
            pass


class HttpsPool:
    """Process-wide pooled HTTPS with redirect following + GET coalescing."""

    def __init__(
        self,
        *,
        max_per_host: int | None = None,
        timeout: float = 60.0,
        max_redirects: int = 8,
    ) -> None:
        if max_per_host is None:
            max_per_host = int(os.environ.get("LIGHTWELL_HTTP_POOL_SIZE", "8"))
        self.max_per_host = max(1, max_per_host)
        self.timeout = timeout
        self.max_redirects = max_redirects
        self._pools: dict[tuple[str, int], _HostPool] = {}
        self._pools_lock = threading.Lock()
        self._inflight: dict[str, threading.Event] = {}
        self._inflight_results: dict[str, tuple[int, str, dict[str, str]] | BaseException] = {}
        self._inflight_waiters: dict[str, int] = {}
        self._inflight_lock = threading.Lock()

    def _pool_for(self, host: str, port: int) -> _HostPool:
        key = (host, port)
        with self._pools_lock:
            pool = self._pools.get(key)
            if pool is None:
                pool = _HostPool(host, port, maxsize=self.max_per_host, timeout=self.timeout)
                self._pools[key] = pool
            return pool

    def request(
        self,
        url: str,
        *,
        headers: dict[str, str],
        method: str = "GET",
    ) -> tuple[int, str, dict[str, str]]:
        """Return (status, body, headers). Follows redirects. Coalesces identical GETs."""
        if method.upper() != "GET":
            return self._request_uncached(url, headers=headers, method=method)

        with self._inflight_lock:
            existing = self._inflight.get(url)
            if existing is not None:
                event = existing
                self._inflight_waiters[url] = self._inflight_waiters.get(url, 0) + 1
                leader = False
            else:
                event = threading.Event()
                self._inflight[url] = event
                self._inflight_waiters[url] = 0
                leader = True

        if not leader:
            try:
                event.wait(timeout=self.timeout * (self.max_redirects + 2))
                with self._inflight_lock:
                    result = self._inflight_results.get(url)
                if isinstance(result, BaseException):
                    raise result
                if result is None:
                    raise HttpFetchError(f"coalesced GET produced no result: {url}")
                return result
            finally:
                with self._inflight_lock:
                    left = self._inflight_waiters.get(url, 1) - 1
                    if left <= 0:
                        self._inflight_waiters.pop(url, None)
                        self._inflight_results.pop(url, None)
                    else:
                        self._inflight_waiters[url] = left

        try:
            result = self._request_uncached(url, headers=headers, method=method)
            with self._inflight_lock:
                self._inflight_results[url] = result
            return result
        except BaseException as exc:
            with self._inflight_lock:
                self._inflight_results[url] = exc
            raise
        finally:
            event.set()
            with self._inflight_lock:
                self._inflight.pop(url, None)
                # Drop result only when no followers remain
                if self._inflight_waiters.get(url, 0) <= 0:
                    self._inflight_waiters.pop(url, None)
                    self._inflight_results.pop(url, None)

    def _request_uncached(
        self,
        url: str,
        *,
        headers: dict[str, str],
        method: str,
    ) -> tuple[int, str, dict[str, str]]:
        current = url
        # Auth / conditional headers only on the first hop (origin); CDN signed
        # URLs should not get Basic auth re-sent in a way that breaks signatures.
        first_headers = dict(headers)

        for _ in range(self.max_redirects + 1):
            parsed = urlparse(current)
            if parsed.scheme != "https":
                raise HttpFetchError(f"only https supported (got {parsed.scheme})")
            host = parsed.hostname
            if not host:
                raise HttpFetchError(f"bad url: {current}")
            port = parsed.port or 443
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"

            pool = self._pool_for(host, port)
            conn = pool.acquire()
            discard = False
            try:
                conn.request(method.upper(), path, headers=first_headers)
                resp = conn.getresponse()
                status = int(resp.status)
                raw = resp.read()
                resp_headers = {k: v for k, v in resp.getheaders()}
                body = raw.decode("utf-8", errors="replace")
                conn_hdr = (resp_headers.get("Connection") or resp_headers.get("connection") or "").lower()
                if conn_hdr == "close" or status >= 500 or status in {401, 403}:
                    discard = True

                if status in {301, 302, 303, 307, 308}:
                    loc = resp_headers.get("Location") or resp_headers.get("location")
                    if not loc:
                        raise HttpFetchError(f"redirect without Location: HTTP {status}")
                    current = urljoin(current, loc)
                    # Subsequent hops: drop Authorization (CDN / signed URLs)
                    first_headers = {k: v for k, v in first_headers.items() if k.lower() not in {"authorization"}}
                    continue

                return status, body, resp_headers
            except (OSError, http.client.HTTPException) as exc:
                discard = True
                raise HttpFetchError(str(exc)) from exc
            finally:
                pool.release(conn, discard=discard)

        raise HttpFetchError(f"too many redirects for {url}")


_POOL: HttpsPool | None = None
_POOL_LOCK = threading.Lock()


def shared_https_pool() -> HttpsPool:
    global _POOL
    with _POOL_LOCK:
        if _POOL is None:
            _POOL = HttpsPool()
        return _POOL


def basic_auth_header(username: str, token: str) -> str:
    token_b64 = base64.b64encode(f"{username}:{token}".encode()).decode("ascii")
    return f"Basic {token_b64}"
