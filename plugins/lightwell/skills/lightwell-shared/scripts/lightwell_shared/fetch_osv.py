"""Fetch Lightwell remediated OSV advisories and match version bumps.

Credentials from LIGHTWELL_USERNAME / LIGHTWELL_TOKEN (never printed).
Uses http_pool via download_http.

Usage:
  fetch_osv.py <groupId> <artifactId> <fromVersion> <toVersion> [...]
  fetch_osv.py --no-cache -v <g> <a> <from> <to>

Stdout: groupId:artifactId|CVE-…|summary|fixed=<to>|osv=<url>
Requires Python 3.14+.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

import lightwell_shared.match_osv_cves as matcher
from lightwell_shared.download_http import HttpAuthError, auth_get, download_to_path, header_value
from lightwell_shared.lightwell_urls import OSV_REMEDIATED_BASE
from lightwell_shared.match_osv_cves import advisories_for_bumps, load_bumps
from lightwell_shared.runtime import require_python
from lightwell_shared.thread_jobs import map_threaded

_JSON_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.json$")


def osv_cache_root(*, no_cache: bool) -> Path | None:
    if no_cache or os.environ.get("LIGHTWELL_OSV_NO_CACHE") == "1":
        return None
    override = os.environ.get("LIGHTWELL_OSV_CACHE_DIR", "").strip()
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_CACHE_HOME", "").strip() or str(Path.home() / ".cache")
    return Path(xdg) / "lightwell-osv"


def parse_manifest(manifest: str) -> list[tuple[str, str]]:
    """Return [(filename, checksum), ...] for advisory JSON entries."""
    out: list[tuple[str, str]] = []
    for line in manifest.splitlines():
        line = line.strip()
        if not line:
            continue
        name, _, rest = line.partition(",")
        checksum, _, _ = rest.partition(",")
        if not _JSON_NAME_RE.match(name) or not checksum:
            continue
        out.append((name, checksum))
    return out


def load_manifest(
    *,
    cache_dir: Path | None,
    ttl: int,
    username: str,
    token: str,
    verbose: bool,
) -> str:
    base = OSV_REMEDIATED_BASE
    manifest_url = f"{base}/PULP_MANIFEST"
    man_path = cache_dir / "PULP_MANIFEST" if cache_dir else None
    fetched_path = cache_dir / "PULP_MANIFEST.fetched_at" if cache_dir else None
    etag_path = cache_dir / "PULP_MANIFEST.etag" if cache_dir else None

    if man_path and fetched_path and man_path.is_file() and fetched_path.is_file():
        try:
            age = time.time() - int(fetched_path.read_text(encoding="utf-8").strip())
        except ValueError:
            age = ttl + 1
        if 0 <= age < ttl and man_path.stat().st_size > 0:
            if verbose:
                print("Manifest cache hit (TTL)", file=sys.stderr)
            return man_path.read_text(encoding="utf-8")

    etag = None
    if etag_path and etag_path.is_file():
        etag = etag_path.read_text(encoding="utf-8").strip() or None

    status, body, headers = auth_get(manifest_url, username, token, etag=etag)

    if status == 304 and man_path and man_path.is_file():
        if cache_dir is not None:
            (cache_dir / "PULP_MANIFEST.fetched_at").write_text(str(int(time.time())), encoding="utf-8")
        if verbose:
            print("Manifest cache revalidated (304)", file=sys.stderr)
        return man_path.read_text(encoding="utf-8")

    if status != 200 or not body.strip():
        print(f"MANIFEST_FETCH_FAILED: HTTP {status}", file=sys.stderr)
        raise SystemExit(1)

    if cache_dir is not None:
        cache_dir.mkdir(parents=True, exist_ok=True)
        (cache_dir / "advisories").mkdir(parents=True, exist_ok=True)
        (cache_dir / "PULP_MANIFEST").write_text(body, encoding="utf-8")
        (cache_dir / "PULP_MANIFEST.fetched_at").write_text(str(int(time.time())), encoding="utf-8")
        new_etag = header_value(headers, "etag")
        if new_etag:
            (cache_dir / "PULP_MANIFEST.etag").write_text(new_etag + "\n", encoding="utf-8")

    return body


def filter_names_via_index(
    names: list[str],
    *,
    cache_dir: Path,
    manifest_id: str,
    bumps_file: Path,
    verbose: bool,
) -> list[str]:
    index_path = cache_dir / "package-index.json"
    if not index_path.is_file():
        return names
    try:
        cached = json.loads(index_path.read_text(encoding="utf-8"))
    except Exception:
        return names
    if cached.get("manifest_id") != manifest_id:
        return names
    bumps = load_bumps(bumps_file)
    relevant = set(advisories_for_bumps(cached, bumps))
    if not relevant:
        return names
    filtered = [n for n in names if n in relevant]
    if filtered:
        if verbose:
            print(
                f"Using package-index filter: {len(filtered)}/{len(names)} advisories",
                file=sys.stderr,
            )
        return filtered
    return names


def fetch_advisories(
    names: list[str],
    checksums: dict[str, str],
    *,
    base_url: str,
    work_dir: Path,
    cache_dir: Path | None,
    username: str,
    token: str,
    jobs: int,
    verbose: bool,
) -> tuple[int, int]:
    """Download missing advisories into work_dir. Return (ok_count, fail_count)."""
    advisories_dir = work_dir / "advisories"
    advisories_dir.mkdir(parents=True, exist_ok=True)
    need_fetch: list[str] = []

    for name in names:
        want_sha = checksums[name]
        dest = advisories_dir / name
        if cache_dir:
            cached = cache_dir / "advisories" / name
            cached_sha = cache_dir / "advisories" / f"{name}.sha"
            if (
                cached.is_file()
                and cached.stat().st_size > 0
                and cached_sha.is_file()
                and cached_sha.read_text(encoding="utf-8").strip() == want_sha
            ):
                if dest.exists() or dest.is_symlink():
                    dest.unlink()
                try:
                    os.link(cached, dest)
                except OSError:
                    shutil.copy2(cached, dest)
                continue
        need_fetch.append(name)

    if verbose:
        print(
            f"Advisories: {len(names) - len(need_fetch)} cached, {len(need_fetch)} to fetch (jobs={jobs})",
            file=sys.stderr,
        )

    failures: list[str] = []

    def work(_idx: int, name: str) -> tuple[str, bool]:
        dest = advisories_dir / name
        code = download_to_path(f"{base_url}/{name}", dest, username, token)
        if code != 200 or not dest.is_file() or dest.stat().st_size == 0:
            dest.unlink(missing_ok=True)
            return name, False
        if cache_dir:
            adv_cache = cache_dir / "advisories"
            adv_cache.mkdir(parents=True, exist_ok=True)
            shutil.copy2(dest, adv_cache / name)
            (adv_cache / f"{name}.sha").write_text(checksums[name] + "\n", encoding="utf-8")
        return name, True

    if need_fetch:
        for name, ok in map_threaded(
            need_fetch,
            work,
            max_workers=jobs,
            cancel_on=HttpAuthError,
        ):
            if not ok:
                failures.append(name)

    ok_files = list(advisories_dir.glob("*.json"))
    return len(ok_files), len(failures)


def collect_match_lines(
    advisories_dir: Path,
    bumps_file: Path,
    *,
    cache_dir: Path | None,
    manifest_id: str,
    verbose: bool,
) -> list[str]:
    if verbose:
        ok_count = len(list(advisories_dir.glob("*.json")))
        print(f"Matching bumps against {ok_count} advisories", file=sys.stderr)

    bumps = load_bumps(bumps_file)
    if not bumps:
        return []

    index_cache = (cache_dir / "package-index.json") if cache_dir else None
    index = matcher.load_or_build_index(advisories_dir, index_cache, manifest_id)
    advisories, parse_errors = matcher.load_advisories_for_bumps(advisories_dir, bumps, index)
    if parse_errors:
        print(f"PARSE_ERRORS: {parse_errors}", file=sys.stderr)
    lines = matcher.match_bumps(bumps, advisories)
    if not lines:
        print("NO_MATCHING_ADVISORIES", file=sys.stderr)
    return lines


def fetch_osv_lines_for_bumps(
    bumps: list[tuple[str, str, str, str]],
    *,
    username: str | None = None,
    token: str | None = None,
    no_cache: bool = False,
    verbose: bool = False,
) -> list[str]:
    """Library entry: return OSV match lines for version bumps.

    Raises HttpAuthError on 401/403. Raises RuntimeError on fetch/matcher failure.
    """
    if not bumps:
        return []
    user = username if username is not None else os.environ.get("LIGHTWELL_USERNAME", "")
    tok = token if token is not None else os.environ.get("LIGHTWELL_TOKEN", "")
    if not user or not tok:
        raise RuntimeError("CREDS_MISSING")

    jobs = int(os.environ.get("LIGHTWELL_OSV_JOBS", "16"))
    if jobs < 1:
        raise RuntimeError("LIGHTWELL_OSV_JOBS must be >= 1")
    ttl = int(os.environ.get("LIGHTWELL_OSV_CACHE_TTL", "3600"))
    if ttl < 0:
        raise RuntimeError("LIGHTWELL_OSV_CACHE_TTL must be >= 0")

    cache_dir = osv_cache_root(no_cache=no_cache)
    base_url = OSV_REMEDIATED_BASE

    with tempfile.TemporaryDirectory(prefix="lightwell-osv-") as tmp:
        work = Path(tmp)
        bumps_file = work / "bumps.txt"
        bumps_file.write_text(
            "".join(f"{g}:{a} {frm} {to}\n" for g, a, frm, to in bumps),
            encoding="utf-8",
        )

        manifest = load_manifest(
            cache_dir=cache_dir,
            ttl=ttl,
            username=user,
            token=tok,
            verbose=verbose,
        )
        entries = parse_manifest(manifest)
        if not entries:
            raise RuntimeError("MANIFEST_EMPTY")

        checksums = dict(entries)
        names = [n for n, _ in entries]
        manifest_id = hashlib.sha256(manifest.encode("utf-8")).hexdigest()

        if cache_dir:
            names = filter_names_via_index(
                names,
                cache_dir=cache_dir,
                manifest_id=manifest_id,
                bumps_file=bumps_file,
                verbose=verbose,
            )

        ok_count, fail_count = fetch_advisories(
            names,
            checksums,
            base_url=base_url,
            work_dir=work,
            cache_dir=cache_dir,
            username=user,
            token=tok,
            jobs=jobs,
            verbose=verbose,
        )
        total = len(names)
        if ok_count == 0:
            raise RuntimeError(f"DOWNLOADS_FAILED: 0/{total} advisories fetched")
        if fail_count > 0:
            print(
                f"DOWNLOADS_PARTIAL: {fail_count}/{total} advisories failed",
                file=sys.stderr,
            )

        return collect_match_lines(
            work / "advisories",
            bumps_file,
            cache_dir=cache_dir,
            manifest_id=manifest_id,
            verbose=verbose,
        )


def main() -> int:
    require_python()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument(
        "coords",
        nargs="+",
        help="groupId artifactId fromVersion toVersion (repeatable)",
    )
    args = parser.parse_args()

    if len(args.coords) < 4 or len(args.coords) % 4 != 0:
        print(
            "error: arguments must be in sets of four (groupId artifactId fromVersion toVersion)",
            file=sys.stderr,
        )
        return 2

    bumps: list[tuple[str, str, str, str]] = []
    coords = list(args.coords)
    for i in range(0, len(coords), 4):
        g, a, frm, to = coords[i : i + 4]
        bumps.append((g, a, frm, to))

    try:
        lines = fetch_osv_lines_for_bumps(
            bumps,
            no_cache=args.no_cache,
            verbose=args.verbose,
        )
    except HttpAuthError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    for line in lines:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
