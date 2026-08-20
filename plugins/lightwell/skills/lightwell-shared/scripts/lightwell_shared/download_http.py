"""Authenticated HTTPS GETs via http_pool (OSV + provenance downloads).

Never prints credentials. Requires Python 3.14+.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from lightwell_shared.http_pool import HttpFetchError, basic_auth_header, shared_https_pool
from lightwell_shared.lightwell_urls import provenance_bundle_url
from lightwell_shared.runtime import require_python

_NO_STORE_HEADERS = {
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}


class HttpAuthError(Exception):
    """HTTP 401/403 from packages.redhat.com."""

    def __init__(self, code: int = 403) -> None:
        self.code = code
        super().__init__(f"AUTH_FAILED: HTTP {code} — validate LIGHTWELL_TOKEN")


def auth_get(
    url: str,
    username: str,
    token: str,
    *,
    etag: str | None = None,
) -> tuple[int, str, dict[str, str]]:
    """Return (status, body, headers). Raises HttpAuthError on 401/403."""
    headers = dict(_NO_STORE_HEADERS)
    headers["Authorization"] = basic_auth_header(username, token)
    if etag:
        headers["If-None-Match"] = etag
    try:
        status, body, resp_headers = shared_https_pool().request(url, headers=headers, method="GET")
    except HttpFetchError as exc:
        raise RuntimeError(f"FETCH_FAILED: {exc}") from exc
    if status in (401, 403):
        raise HttpAuthError(status)
    return status, body, resp_headers


def header_value(headers: dict[str, str], name: str) -> str | None:
    needle = name.lower()
    for key, value in headers.items():
        if key.lower() == needle:
            return value.strip()
    return None


def download_to_path(
    url: str,
    dest: Path,
    username: str,
    token: str,
) -> int:
    """GET url and write body to dest on HTTP 200. Return status code.

    Raises HttpAuthError on 401/403. Does not write dest on failure.
    """
    status, body, _headers = auth_get(url, username, token)
    if status != 200 or not body.strip():
        return status
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_name(f".{dest.name}.partial.{os.getpid()}")
    try:
        partial.write_text(body, encoding="utf-8")
        os.replace(partial, dest)
    finally:
        partial.unlink(missing_ok=True)
    return status


def main() -> int:
    """CLI for provenance (and generic) authenticated downloads."""
    require_python()
    parser = argparse.ArgumentParser(description="Download a Lightwell HTTPS resource via http_pool.")
    parser.add_argument("--out", required=True, help="Destination path")
    parser.add_argument(
        "--provenance",
        nargs=4,
        metavar=("CATALOG", "GROUP", "ARTIFACT", "VERSION"),
        help="Build provenance bundle URL from coordinates",
    )
    parser.add_argument(
        "url",
        nargs="?",
        default="",
        help="Explicit URL (omit when using --provenance)",
    )
    args = parser.parse_args()

    username = os.environ.get("LIGHTWELL_USERNAME", "")
    token = os.environ.get("LIGHTWELL_TOKEN", "")
    if not username or not token:
        print("CREDS_MISSING", file=sys.stderr)
        return 1

    if args.provenance:
        catalog, group_id, artifact_id, version = args.provenance
        if catalog not in {"remediated", "validated"}:
            print(f"error: bad catalog: {catalog}", file=sys.stderr)
            return 2
        url = provenance_bundle_url(catalog, group_id, artifact_id, version)
    elif args.url:
        url = args.url
    else:
        print("error: provide URL or --provenance", file=sys.stderr)
        return 2

    dest = Path(args.out)
    try:
        code = download_to_path(url, dest, username, token)
    except HttpAuthError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if code != 200 or not dest.is_file() or dest.stat().st_size == 0:
        print(f"DOWNLOAD_FAILED: HTTP {code}", file=sys.stderr)
        dest.unlink(missing_ok=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
