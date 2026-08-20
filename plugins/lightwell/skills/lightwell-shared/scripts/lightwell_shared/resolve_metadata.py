"""Fetch / cache Lightwell maven-metadata and print versions or XML.

Usage:
  resolve_metadata.py --latest [--ttl SECONDS] [--cache-dir DIR]
                      [--jobs N] [--no-cache]
                      <catalog> <groupId> <artifactId>
  resolve_metadata.py --same-base [--ttl SECONDS] [--cache-dir DIR]
                      [--jobs N] [--no-cache]
                      <catalog> <groupId> <artifactId> <currentVersion>
  resolve_metadata.py [--latest|--same-base] [--ttl SECONDS]
                      [--cache-dir DIR] [--jobs N] [--no-cache] --batch
                      < coords on stdin >

Single --latest/--same-base prints only the version string.
Without a mode flag, prints full maven-metadata.xml.
Batch mode prints: catalog groupId:artifactId -> version

--same-base: highest .rhlw-* on the same upstream base as currentVersion
  (batch lines: catalog groupId artifactId currentVersion).

Credentials from LIGHTWELL_USERNAME / LIGHTWELL_TOKEN (never printed).
Cache stores response bodies and validators only (etag, fetched_at, tag values,
same-base sidecars, negative markers). Never uses HTTP Expires / Cache-Control
response headers for cache decisions. HTTPS uses a keep-alive connection pool
with redirect following and in-flight GET coalescing (see http_pool.py).
Requires Python 3.14+ (skill pin; no version fallbacks).
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
import threading
import time
from pathlib import Path

from lightwell_shared.http_pool import HttpFetchError, basic_auth_header, shared_https_pool
from lightwell_shared.lightwell_urls import maven_metadata_url
from lightwell_shared.pom_lib import RHLW_RE, semver_triple
from lightwell_shared.runtime import require_python
from lightwell_shared.thread_jobs import map_threaded

# Bust intermediary caches on fetch (avoid stale 302 Location with expired S3
# Expires= query params). Not used for local disk-cache decisions.
_NO_STORE_HEADERS = {
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}

_DEFAULT_JOBS = int(os.environ.get("LIGHTWELL_METADATA_JOBS", "16"))


_memo_lock = threading.Lock()
_memo: dict[tuple, str | None] = {}
_cache_locks_guard = threading.Lock()
_cache_locks: dict[str, threading.Lock] = {}


class MetadataError(Exception):
    def __init__(self, message: str, code: int = 1) -> None:
        super().__init__(message)
        self.code = code


class AuthFailedError(MetadataError):
    """HTTP 401/403 from packages.redhat.com — bad or stale LIGHTWELL_TOKEN."""

    def __init__(self, http_code: int = 403) -> None:
        super().__init__(
            f"AUTH_FAILED: HTTP {http_code} — validate LIGHTWELL_TOKEN",
            code=1,
        )
        self.http_code = http_code


def is_auth_error(exc_or_msg: BaseException | str) -> bool:
    """True when the error means credentials were rejected (stop the workflow)."""
    if isinstance(exc_or_msg, AuthFailedError):
        return True
    msg = str(exc_or_msg)
    return msg.startswith("AUTH_FAILED:")


def raise_cached_error(message: str) -> None:
    """Re-raise a memoized error, preserving AuthFailedError for 401/403."""
    if message.startswith("AUTH_FAILED:"):
        # Prefer HTTP code from message when present
        code = 403
        if "HTTP 401" in message:
            code = 401
        elif "HTTP 403" in message:
            code = 403
        raise AuthFailedError(code)
    raise MetadataError(message)


def default_cache_root(no_cache: bool = False) -> Path | None:
    """Return metadata cache root, or None when caching is disabled."""
    if no_cache or os.environ.get("LIGHTWELL_METADATA_NO_CACHE") == "1":
        return None
    override = os.environ.get("LIGHTWELL_METADATA_CACHE_DIR", "")
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(xdg) / "lightwell-metadata"


def default_natural_cache_root(no_cache: bool = False) -> Path | None:
    """Return natural-tree cache root, or None when caching is disabled."""
    if no_cache or os.environ.get("LIGHTWELL_NATURAL_NO_CACHE") == "1":
        return None
    override = os.environ.get("LIGHTWELL_NATURAL_CACHE_DIR", "")
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(xdg) / "lightwell-natural"


def extract_tag(xml: str, tag: str) -> str | None:
    match = re.search(rf"<{re.escape(tag)}>([^<]+)</{re.escape(tag)}>", xml)
    if not match:
        return None
    return match.group(1).strip()


def extract_versions(xml: str) -> list[str]:
    block = re.search(r"<versions>(.*?)</versions>", xml, re.DOTALL)
    if not block:
        return []
    return [m.group(1).strip() for m in re.finditer(r"<version>([^<]+)</version>", block.group(1))]


def upstream_base(version: str) -> str:
    match = RHLW_RE.match(version)
    return match.group("base") if match else version


def highest_rhlw_on_base(versions: list[str], current: str) -> str | None:
    """Newest .rhlw-* on the same upstream base / SemVer triple as current.

    Matches exact base string first; otherwise SemVer major.minor.patch
    (so `20220320` matches `20220320.0.0.rhlw-*`). Never invents versions.
    """
    base = upstream_base(current)
    cur_sem = semver_triple(current)
    best: str | None = None
    best_n = -1
    for ver in versions:
        match = RHLW_RE.match(ver)
        if not match:
            continue
        ver_base = match.group("base")
        if ver_base != base:
            if cur_sem is None or semver_triple(ver) != cur_sem:
                continue
        n = int(match.group("n"))
        if n > best_n:
            best_n = n
            best = ver
    return best


def header_value(headers: dict[str, str], name: str) -> str | None:
    """Return a response header (case-insensitive)."""
    needle = name.lower()
    for key, value in headers.items():
        if key.lower() == needle:
            return value.strip()
    return None


def coord_cache_dir(cache_root: Path, catalog: str, group_id: str, artifact_id: str) -> Path:
    group_path = Path(*group_id.split("."))
    return cache_root / catalog / group_path / artifact_id


def natural_coord_cache_dir(cache_root: Path, group_id: str, artifact_id: str, version: str) -> Path:
    group_path = Path(*group_id.split("."))
    # Version may contain characters awkward for paths; keep readable but safe.
    safe_ver = version.replace("/", "_")
    return cache_root / group_path / artifact_id / safe_ver


def same_base_sidecar_name(current: str) -> str:
    digest = hashlib.sha256(current.encode("utf-8")).hexdigest()[:16]
    return f"same-base-{digest}"


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}.{time.time_ns()}")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def cache_dir_lock(cdir: Path) -> threading.Lock:
    key = str(cdir)
    with _cache_locks_guard:
        lock = _cache_locks.get(key)
        if lock is None:
            lock = threading.Lock()
            _cache_locks[key] = lock
        return lock


def cache_fresh(cdir: Path, ttl: int) -> bool:
    fetched = read_text(cdir / "fetched_at")
    if not fetched:
        return False
    try:
        age = time.time() - int(fetched.strip())
    except ValueError:
        return False
    return 0 <= age < ttl


def negative_ttl() -> int:
    return int(os.environ.get("LIGHTWELL_METADATA_NEGATIVE_TTL", "120"))


def read_negative(cdir: Path, ttl: int) -> str | None:
    if not cache_fresh(cdir, ttl):
        return None
    reason = read_text(cdir / "negative")
    if not reason or not reason.strip():
        return None
    return reason.strip()


def write_negative(cdir: Path | None, reason: str) -> None:
    if cdir is None:
        return
    with cache_dir_lock(cdir):
        write_text_atomic(cdir / "negative", reason)
        write_text_atomic(cdir / "fetched_at", str(int(time.time())))


def clear_negative(cdir: Path) -> None:
    (cdir / "negative").unlink(missing_ok=True)


def fetch_metadata_http(
    url: str,
    username: str,
    token: str,
    etag: str | None,
) -> tuple[int, str, dict[str, str]]:
    """Return (http_code, body, response_headers).

    Uses a process-wide pooled HTTPS client (keep-alive + redirect follow +
    in-flight GET coalescing). No curl subprocess.
    """
    headers = dict(_NO_STORE_HEADERS)
    headers["Authorization"] = basic_auth_header(username, token)
    if etag:
        headers["If-None-Match"] = etag
    try:
        return shared_https_pool().request(url, headers=headers, method="GET")
    except HttpFetchError as exc:
        raise MetadataError(f"METADATA_FETCH_FAILED: {exc}") from exc


def resolve_one(
    catalog: str,
    group_id: str,
    artifact_id: str,
    *,
    tag: str | None,
    cache_root: Path | None,
    ttl: int,
    username: str,
    token: str,
) -> str:
    """Return version string or full XML."""
    url = maven_metadata_url(catalog, group_id, artifact_id)
    cdir = coord_cache_dir(cache_root, catalog, group_id, artifact_id) if cache_root else None
    neg_ttl = negative_ttl()

    if cdir:
        neg = read_negative(cdir, neg_ttl)
        if neg:
            raise MetadataError(neg if neg.startswith("METADATA_") else f"METADATA_FETCH_FAILED: {neg}")

    xml: str | None = None
    if cdir and cache_fresh(cdir, ttl) and not (cdir / "negative").is_file():
        if tag:
            cached_tag = read_text(cdir / tag)
            if cached_tag and cached_tag.strip():
                return cached_tag.strip()
        xml = read_text(cdir / "maven-metadata.xml")

    if xml is None:
        etag = read_text(cdir / "etag") if cdir else None
        etag = etag.strip() if etag else None
        code, body, headers = fetch_metadata_http(url, username, token, etag)
        if code == 304 and cdir:
            xml = read_text(cdir / "maven-metadata.xml")
            if not xml:
                raise MetadataError("METADATA_FETCH_FAILED: 304 without cache")
            with cache_dir_lock(cdir):
                write_text_atomic(cdir / "fetched_at", str(int(time.time())))
                clear_negative(cdir)
                # Keep tag sidecars warm from XML when missing
                for t in ("latest", "release"):
                    if not (cdir / t).is_file():
                        val = extract_tag(xml, t)
                        if val:
                            write_text_atomic(cdir / t, val)
        elif code == 200:
            if not body.strip():
                write_negative(cdir, "METADATA_EMPTY")
                raise MetadataError("METADATA_EMPTY")
            xml = body
            if cdir:
                with cache_dir_lock(cdir):
                    clear_negative(cdir)
                    write_text_atomic(cdir / "maven-metadata.xml", xml)
                    write_text_atomic(cdir / "fetched_at", str(int(time.time())))
                    new_etag = header_value(headers, "etag")
                    if new_etag:
                        write_text_atomic(cdir / "etag", new_etag)
                    for t in ("latest", "release"):
                        val = extract_tag(xml, t)
                        if val:
                            write_text_atomic(cdir / t, val)
        elif code == 404:
            write_negative(cdir, "HTTP 404")
            raise MetadataError("METADATA_FETCH_FAILED: HTTP 404")
        elif code in (401, 403):
            # Do not negative-cache auth failures (bad/stale LIGHTWELL_TOKEN)
            raise AuthFailedError(code)
        else:
            # Do not negative-cache transient 5xx
            raise MetadataError(f"METADATA_FETCH_FAILED: HTTP {code}")

    assert xml is not None
    if not xml.strip():
        write_negative(cdir, "METADATA_EMPTY")
        raise MetadataError("METADATA_EMPTY")

    if tag is None:
        return xml

    value = extract_tag(xml, tag)
    if not value:
        raise MetadataError(f"NO_{tag}")
    if cdir:
        with cache_dir_lock(cdir):
            write_text_atomic(cdir / tag, value)
            if not (cdir / "maven-metadata.xml").exists():
                write_text_atomic(cdir / "maven-metadata.xml", xml)
            if not (cdir / "fetched_at").exists():
                write_text_atomic(cdir / "fetched_at", str(int(time.time())))
    return value


def resolve_payload(
    catalog: str,
    group_id: str,
    artifact_id: str,
    *,
    tag: str | None,
    same_base_current: str | None,
    cache_root: Path | None,
    ttl: int,
    username: str,
    token: str,
) -> str:
    memo_key = (catalog, group_id, artifact_id, tag, same_base_current, str(cache_root), ttl)
    with _memo_lock:
        if memo_key in _memo:
            cached = _memo[memo_key]
            if cached is not None and cached.startswith("__ERR__:"):
                raise_cached_error(cached[len("__ERR__:") :])
            if cached:
                return cached

    cdir = coord_cache_dir(cache_root, catalog, group_id, artifact_id) if cache_root else None

    try:
        if same_base_current is not None and cdir is not None:
            sidecar = cdir / same_base_sidecar_name(same_base_current)
            if cache_fresh(cdir, ttl) and sidecar.is_file():
                picked = read_text(sidecar)
                if picked is not None:
                    text = picked.strip()
                    if text == "NO_SAME_BASE_RHLW":
                        raise MetadataError("NO_SAME_BASE_RHLW")
                    if text:
                        with _memo_lock:
                            _memo[memo_key] = text
                        return text

        xml_or_tag = resolve_one(
            catalog,
            group_id,
            artifact_id,
            tag=None if same_base_current else tag,
            cache_root=cache_root,
            ttl=ttl,
            username=username,
            token=token,
        )
        if same_base_current is None:
            with _memo_lock:
                _memo[memo_key] = xml_or_tag
            return xml_or_tag

        picked = highest_rhlw_on_base(extract_versions(xml_or_tag), same_base_current)
        if not picked:
            if cdir is not None:
                with cache_dir_lock(cdir):
                    write_text_atomic(
                        cdir / same_base_sidecar_name(same_base_current),
                        "NO_SAME_BASE_RHLW",
                    )
            raise MetadataError("NO_SAME_BASE_RHLW")
        if cdir is not None:
            with cache_dir_lock(cdir):
                write_text_atomic(
                    cdir / same_base_sidecar_name(same_base_current),
                    picked,
                )
        with _memo_lock:
            _memo[memo_key] = picked
        return picked
    except MetadataError as exc:
        with _memo_lock:
            _memo[memo_key] = f"__ERR__:{exc}"
        raise


def parse_coords(
    lines: list[str],
    *,
    same_base: bool,
) -> list[tuple[str, str, str, str | None]]:
    """Return (catalog, groupId, artifactId, currentVersion|None)."""
    expected = 4 if same_base else 3
    shape = "catalog groupId artifactId currentVersion" if same_base else "catalog groupId artifactId"
    out: list[tuple[str, str, str, str | None]] = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != expected:
            raise MetadataError(f"error: expected {shape} (got: {line})", 2)
        catalog, group_id, artifact_id = parts[0], parts[1], parts[2]
        current = parts[3] if same_base else None
        if catalog not in {"remediated", "validated"}:
            raise MetadataError(
                f"error: catalog must be remediated or validated (got: {catalog})",
                2,
            )
        out.append((catalog, group_id, artifact_id, current))
    return out


def main() -> int:
    require_python()
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--latest", action="store_true")
    parser.add_argument(
        "--same-base",
        action="store_true",
        help="Pick highest .rhlw-* on currentVersion's upstream base",
    )
    parser.add_argument("--batch", action="store_true")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument(
        "--ttl",
        type=int,
        default=int(os.environ.get("LIGHTWELL_METADATA_CACHE_TTL", "3600")),
    )
    parser.add_argument("--cache-dir", default=os.environ.get("LIGHTWELL_METADATA_CACHE_DIR", ""))
    parser.add_argument(
        "--jobs",
        type=int,
        default=_DEFAULT_JOBS,
    )
    parser.add_argument("coords", nargs="*")
    args = parser.parse_args()

    try:
        mode_flags = sum(bool(x) for x in (args.latest, args.same_base))
        if mode_flags > 1:
            raise MetadataError(
                "error: only one of --latest or --same-base is allowed",
                2,
            )
        tag = "latest" if args.latest else None

        if args.ttl < 0:
            raise MetadataError("error: --ttl must be >= 0", 2)
        if args.jobs < 1:
            raise MetadataError("error: --jobs must be a positive integer", 2)

        username = os.environ.get("LIGHTWELL_USERNAME", "")
        token = os.environ.get("LIGHTWELL_TOKEN", "")
        if not username or not token:
            raise MetadataError("CREDS_MISSING")

        if args.no_cache:
            cache_root = None
        elif args.cache_dir:
            cache_root = Path(args.cache_dir)
        else:
            cache_root = default_cache_root(False)

        if args.batch:
            coords = parse_coords(sys.stdin.read().splitlines(), same_base=args.same_base)
            if not coords:
                raise MetadataError(
                    "error: --batch requires coordinate lines on stdin",
                    2,
                )
            if tag is None and not args.same_base:
                raise MetadataError(
                    "error: --batch requires --latest or --same-base",
                    2,
                )
        else:
            expected = 4 if args.same_base else 3
            if len(args.coords) != expected:
                shape = "catalog groupId artifactId currentVersion" if args.same_base else "catalog groupId artifactId"
                raise MetadataError(f"error: expected {shape}", 2)
            coords = parse_coords([" ".join(args.coords)], same_base=args.same_base)

        # Single coordinate: skill-compatible (version only, or full XML).
        if len(coords) == 1 and not args.batch:
            c, g, a, current = coords[0]
            payload = resolve_payload(
                c,
                g,
                a,
                tag=tag,
                same_base_current=current,
                cache_root=cache_root,
                ttl=args.ttl,
                username=username,
                token=token,
            )
            if tag is None and current is None:
                print(payload, end="" if payload.endswith("\n") else "\n")
            else:
                print(payload)
            return 0

        if tag is None and not args.same_base:
            raise MetadataError(
                "error: multiple coordinates require --latest or --same-base",
                2,
            )

        results: dict[tuple[str, str, str], str] = {}
        errors: list[tuple[tuple[str, str, str], str]] = []

        def work(
            _idx: int,
            item: tuple[str, str, str, str | None],
        ) -> tuple[tuple[str, str, str], str | None, str | None]:
            c, g, a, current = item
            key = (c, g, a)
            try:
                payload = resolve_payload(
                    c,
                    g,
                    a,
                    tag=tag,
                    same_base_current=current,
                    cache_root=cache_root,
                    ttl=args.ttl,
                    username=username,
                    token=token,
                )
                return key, payload, None
            except AuthFailedError:
                raise
            except MetadataError as exc:
                return key, None, str(exc)

        for key, payload_or_none, err in map_threaded(
            coords,
            work,
            max_workers=args.jobs,
            cancel_on=AuthFailedError,
        ):
            if err or payload_or_none is None:
                if err and is_auth_error(err):
                    raise AuthFailedError()
                errors.append((key, err or "MISSING"))
            else:
                results[key] = payload_or_none

        for item in coords:
            c, g, a, _current = item
            key = (c, g, a)
            if key in results:
                print(f"{c} {g}:{a} -> {results[key]}")
            else:
                print(f"{c} {g}:{a} -> MISSING")

        return 1 if errors else 0
    except AuthFailedError as exc:
        print(str(exc), file=sys.stderr)
        return exc.code
    except MetadataError as exc:
        print(str(exc), file=sys.stderr)
        return exc.code


if __name__ == "__main__":
    raise SystemExit(main())
