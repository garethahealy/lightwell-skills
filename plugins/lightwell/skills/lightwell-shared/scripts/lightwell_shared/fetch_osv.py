"""Fetch Lightwell remediated advisories and match version bumps.

Advisory reads use the Lightwell API (``LIGHTWELL_CLIENT_ID`` /
``LIGHTWELL_CLIENT_SECRET``). Reads GET /advisories. Stdout lines still point
``osv=`` at the remediated advisory JSON on packages.redhat.com.

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
import sys
import time
from pathlib import Path
from typing import Any

import lightwell_shared.match_osv_cves as matcher
from lightwell_shared.download_http import HttpAuthError
from lightwell_shared.lightwell_api import ApiError, TermsRequiredError, list_advisories, require_client_credentials
from lightwell_shared.lightwell_urls import OSV_REMEDIATED_BASE
from lightwell_shared.runtime import require_python
from lightwell_shared.thread_jobs import map_threaded


def osv_cache_root(*, no_cache: bool) -> Path | None:
    if no_cache or os.environ.get("LIGHTWELL_OSV_NO_CACHE") == "1":
        return None
    override = os.environ.get("LIGHTWELL_OSV_CACHE_DIR", "").strip()
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_CACHE_HOME", "").strip() or str(Path.home() / ".cache")
    return Path(xdg) / "lightwell-osv"


def _cache_path(cache_dir: Path, package: str) -> Path:
    digest = hashlib.sha256(package.encode("utf-8")).hexdigest()[:16]
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in package)
    return cache_dir / "packages" / f"{safe}-{digest}.json"


def _read_cached(path: Path, ttl: int) -> list[dict[str, Any]] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        fetched = int(data["fetched_at"])
        advisories = data["advisories"]
    except OSError, ValueError, KeyError, TypeError:
        return None
    age = time.time() - fetched
    if age < 0 or age >= ttl or not isinstance(advisories, list):
        return None
    return [item for item in advisories if isinstance(item, dict)]


def _write_cached(path: Path, advisories: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"fetched_at": int(time.time()), "advisories": advisories}
    path.write_text(json.dumps(payload), encoding="utf-8")


def package_names(package_name: object) -> set[str]:
    """Names that identify one Maven package on an advisory record."""
    if not isinstance(package_name, str):
        return set()
    name = package_name.strip()
    if not name:
        return set()
    names = {name}
    if name.startswith("pkg:maven/"):
        body = name[len("pkg:maven/") :].split("@", 1)[0]
        names.add(body.replace("/", ":"))
    elif "/" in name and not name.startswith("pkg:"):
        names.add(name.replace("/", ":"))
    return names


def advisory_tuple(package: str, advisory: dict[str, Any]) -> tuple | None:
    """Map one API advisory onto the tuple ``match_bumps`` already consumes."""
    names = package_names(advisory.get("package_name"))
    if package not in names:
        return None
    raw_fixes = advisory.get("fixed_versions")
    fixes: set[str] = set()
    if isinstance(raw_fixes, list):
        for item in raw_fixes:
            if isinstance(item, str) and item:
                fixes.add(item)
    if not fixes:
        return None
    raw_id = advisory.get("advisory_id")
    advisory_id = raw_id.strip() if isinstance(raw_id, str) and raw_id.strip() else "UNKNOWN"
    file_name = advisory_id if advisory_id.endswith(".json") else f"{advisory_id}.json"
    aliases = advisory.get("aliases")
    if not isinstance(aliases, list):
        aliases = []
    labels = matcher.advisory_labels({"id": advisory_id.removesuffix(".json"), "aliases": aliases})
    summary = matcher.advisory_summary(
        {"summary": advisory.get("summary") or "", "details": advisory.get("details") or ""}
    )
    url = f"{OSV_REMEDIATED_BASE}/{file_name}"
    return ([(names, fixes)], labels, summary, url)


def match_lines_for_advisories(
    bumps: list[tuple[str, str, str, str]],
    advisories_by_package: dict[str, list[dict[str, Any]]],
) -> list[str]:
    """Return stdout lines for bumps. Equal from/to pairs are ignored."""
    triples: list[tuple[str, str, str]] = []
    tuples: list = []
    seen_packages: set[str] = set()
    for group_id, artifact_id, from_ver, to_ver in bumps:
        if from_ver == to_ver:
            continue
        package = f"{group_id}:{artifact_id}"
        triples.append((package, from_ver, to_ver))
        if package in seen_packages:
            continue
        seen_packages.add(package)
        rows = advisories_by_package.get(package) or []
        ordered = sorted(rows, key=lambda item: str(item.get("advisory_id") or ""))
        for advisory in ordered:
            parsed = advisory_tuple(package, advisory)
            if parsed is not None:
                tuples.append(parsed)
    return matcher.match_bumps(triples, tuples)


def _load_package_advisories(
    group_id: str,
    artifact_id: str,
    *,
    cache_dir: Path | None,
    ttl: int,
    verbose: bool,
) -> list[dict[str, Any]]:
    package = f"{group_id}:{artifact_id}"
    path = _cache_path(cache_dir, package) if cache_dir is not None else None
    if path is not None:
        cached = _read_cached(path, ttl)
        if cached is not None:
            if verbose:
                print(f"Advisory cache hit {package}", file=sys.stderr)
            return cached
    try:
        rows = list_advisories(group_id, artifact_id)
    except HttpAuthError, TermsRequiredError:
        raise
    except ApiError as exc:
        if str(exc).startswith("AUTH_FAILED:"):
            raise
        raise RuntimeError(f"ADVISORY_FETCH_FAILED: {exc}") from exc
    if path is not None:
        _write_cached(path, rows)
    return rows


def fetch_osv_lines_for_bumps(
    bumps: list[tuple[str, str, str, str]],
    *,
    no_cache: bool = False,
    verbose: bool = False,
) -> list[str]:
    """Library entry: return OSV match lines for version bumps.

    Raises HttpAuthError on 401/403. Raises ApiError when the message starts
    with ``AUTH_FAILED:`` (missing client credentials or a token-endpoint
    failure). Raises TermsRequiredError when terms block the API. Raises
    RuntimeError on other fetch failures.
    """
    if not bumps:
        return []
    require_client_credentials()

    jobs = int(os.environ.get("LIGHTWELL_OSV_JOBS", "16"))
    if jobs < 1:
        raise RuntimeError("LIGHTWELL_OSV_JOBS must be >= 1")
    ttl = int(os.environ.get("LIGHTWELL_OSV_CACHE_TTL", "3600"))
    if ttl < 0:
        raise RuntimeError("LIGHTWELL_OSV_CACHE_TTL must be >= 0")

    packages: list[tuple[str, str]] = []
    seen: set[str] = set()
    for group_id, artifact_id, from_ver, to_ver in bumps:
        if from_ver == to_ver:
            continue
        package = f"{group_id}:{artifact_id}"
        if package in seen:
            continue
        seen.add(package)
        packages.append((group_id, artifact_id))
    if not packages:
        return []

    cache_dir = osv_cache_root(no_cache=no_cache)
    if verbose:
        print(f"Advisories: {len(packages)} package(s) (jobs={jobs})", file=sys.stderr)

    def work(_idx: int, item: tuple[str, str]) -> list[dict[str, Any]]:
        group_id, artifact_id = item
        return _load_package_advisories(
            group_id,
            artifact_id,
            cache_dir=cache_dir,
            ttl=ttl,
            verbose=verbose,
        )

    fetched = map_threaded(
        packages,
        work,
        max_workers=jobs,
        cancel_on=(HttpAuthError, TermsRequiredError, ApiError),
    )
    by_package = {
        f"{group_id}:{artifact_id}": rows for (group_id, artifact_id), rows in zip(packages, fetched, strict=True)
    }
    lines = match_lines_for_advisories(bumps, by_package)
    if not lines:
        print("NO_MATCHING_ADVISORIES", file=sys.stderr)
    return lines


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
    for index in range(0, len(coords), 4):
        group_id, artifact_id, from_ver, to_ver = coords[index : index + 4]
        bumps.append((group_id, artifact_id, from_ver, to_ver))

    try:
        lines = fetch_osv_lines_for_bumps(
            bumps,
            no_cache=args.no_cache,
            verbose=args.verbose,
        )
    except (HttpAuthError, ApiError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (TermsRequiredError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    for line in lines:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
