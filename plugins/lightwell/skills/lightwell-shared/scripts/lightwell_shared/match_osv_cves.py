"""Match Lightwell remediated OSV advisories against version bumps.

Used as a library by ``fetch_osv``. ``main()`` can still match a directory of
advisory JSON against a bumps file (lines: ``groupId:artifactId from to``).

When --index-cache is set, maintains a JSON package→advisory map keyed by
--manifest-id so unchanged advisory trees skip full rescans.

Prints one stdout line per matching CVE / advisory id:
  groupId:artifactId|CVE-…|summary|fixed=<toVersion>|osv=<advisory-url>

The osv= URL points at the Lightwell remediated advisory JSON on
packages.redhat.com so readers can verify the match.

Exit codes:
  0  success (including zero matches)
  2  usage error

Requires Python 3.14+.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from lightwell_shared.lightwell_urls import OSV_REMEDIATED_BASE as OSV_ADVISORY_BASE
from lightwell_shared.runtime import require_python


def package_names_for_affected(affected_entry: dict) -> set[str]:
    names: set[str] = set()
    pkg = affected_entry.get("package") or {}
    name = pkg.get("name") or ""
    if name:
        names.add(name)
    purl = pkg.get("purl") or ""
    if purl.startswith("pkg:maven/"):
        body = purl[len("pkg:maven/") :].split("@", 1)[0]
        names.add(body.replace("/", ":"))
    return names


def fixed_in_ranges(affected_entry: dict) -> set[str]:
    out: set[str] = set()
    for r in affected_entry.get("ranges") or []:
        for ev in r.get("events") or []:
            if "fixed" in ev:
                out.add(ev["fixed"])
    return out


def advisory_labels(data: dict) -> list[str]:
    aliases = data.get("aliases") or []
    cves = [a for a in aliases if isinstance(a, str) and a.startswith("CVE-")]
    if cves:
        return cves
    return [data.get("id") or "UNKNOWN"]


def advisory_summary(data: dict, limit: int = 200) -> str:
    summary = (data.get("summary") or "").strip()
    if not summary:
        summary = (data.get("details") or "").strip()
    summary = " ".join(summary.split())
    if len(summary) > limit:
        return summary[: limit - 3] + "..."
    return summary


def load_bumps(bumps_path: Path) -> list[tuple[str, str, str]]:
    bumps: list[tuple[str, str, str]] = []
    for line in bumps_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        pkg, from_ver, to_ver = line.split()
        if from_ver == to_ver:
            continue
        bumps.append((pkg, from_ver, to_ver))
    return bumps


def advisory_url(path: Path) -> str:
    return f"{OSV_ADVISORY_BASE}/{path.name}"


def parse_advisory(
    path: Path,
) -> tuple[list[tuple[set[str], set[str]]], list[str], str, set[str], str] | None:
    try:
        data = json.loads(path.read_text())
    except Exception:
        return None
    entries: list[tuple[set[str], set[str]]] = []
    all_names: set[str] = set()
    for affected in data.get("affected") or []:
        names = package_names_for_affected(affected)
        fixes = fixed_in_ranges(affected)
        if names and fixes:
            entries.append((names, fixes))
            all_names |= names
    if not entries:
        return None
    return (
        entries,
        advisory_labels(data),
        advisory_summary(data),
        all_names,
        advisory_url(path),
    )


def build_index(root: Path) -> dict[str, Any]:
    packages: dict[str, list[str]] = {}
    parse_errors = 0
    for path in sorted(root.glob("*.json")):
        try:
            json.loads(path.read_text())
        except Exception:
            parse_errors += 1
            continue
        parsed = parse_advisory(path)
        if parsed is None:
            continue
        _entries, _labels, _summary, names, _url = parsed
        for name in names:
            packages.setdefault(name, []).append(path.name)
    for name in packages:
        packages[name] = sorted(set(packages[name]))
    return {"packages": packages, "parse_errors": parse_errors}


def load_or_build_index(
    root: Path,
    index_cache: Path | None,
    manifest_id: str | None,
) -> dict[str, Any]:
    if index_cache and manifest_id and index_cache.is_file():
        try:
            cached = json.loads(index_cache.read_text())
            if cached.get("manifest_id") == manifest_id and isinstance(cached.get("packages"), dict):
                return cached
        except Exception:
            pass
    index = build_index(root)
    if index_cache and manifest_id:
        index_cache.parent.mkdir(parents=True, exist_ok=True)
        to_store = {
            "manifest_id": manifest_id,
            "packages": index["packages"],
        }
        index_cache.write_text(json.dumps(to_store, indent=2, sort_keys=True) + "\n")
    return index


def advisories_for_bumps(
    index: dict[str, Any],
    bumps: list[tuple[str, str, str]],
) -> list[str]:
    """Return advisory filenames relevant to bumps from a package index."""
    packages = index.get("packages") or {}
    wanted: set[str] = set()
    for pkg, _f, _t in bumps:
        wanted.update(packages.get(pkg, []))
    return sorted(wanted)


def load_advisories_for_bumps(
    root: Path,
    bumps: list[tuple[str, str, str]],
    index: dict[str, Any] | None,
) -> tuple[list, int]:
    parse_errors = int((index or {}).get("parse_errors") or 0)
    if index and index.get("packages"):
        paths = [root / name for name in advisories_for_bumps(index, bumps)]
    else:
        paths = sorted(root.glob("*.json"))

    advisories = []
    for path in paths:
        if not path.is_file():
            continue
        parsed = parse_advisory(path)
        if parsed is None:
            if index is None:
                parse_errors += 1
            continue
        entries, labels, summary, _names, url = parsed
        advisories.append((entries, labels, summary, url))
    return advisories, parse_errors


def match_bumps(bumps: list[tuple[str, str, str]], advisories: list) -> list[str]:
    """Return stdout-style match lines (does not print)."""
    seen: set[tuple[str, str, str]] = set()
    lines: list[str] = []
    for pkg, from_ver, to_ver in bumps:
        for entries, labels, summary, url in advisories:
            for names, fixes in entries:
                if pkg not in names:
                    continue
                if to_ver not in fixes:
                    continue
                if from_ver in fixes:
                    continue
                for key in labels:
                    row_key = (pkg, key, to_ver)
                    if row_key in seen:
                        continue
                    seen.add(row_key)
                    lines.append(f"{pkg}|{key}|{summary}|fixed={to_ver}|osv={url}")
    return lines


def main() -> int:
    require_python()
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument(
        "osv_dir",
        nargs="?",
        default="",
        help="Directory of advisory JSON (omit with --list-advisories)",
    )
    parser.add_argument(
        "bumps_file",
        nargs="?",
        default="",
        help="Bumps file (or use --bumps with --list-advisories)",
    )
    parser.add_argument("--index-cache", default="")
    parser.add_argument("--manifest-id", default="")
    parser.add_argument(
        "--list-advisories",
        action="store_true",
        help="Print advisory filenames for bumps from --index-cache (no match)",
    )
    parser.add_argument(
        "--bumps",
        default="",
        help="Bumps file for --list-advisories",
    )
    args = parser.parse_args()

    if args.list_advisories:
        bumps_path = Path(args.bumps or args.bumps_file)
        index_cache = Path(args.index_cache) if args.index_cache else None
        if not bumps_path.is_file():
            print(f"error: bumps_file not found: {bumps_path}", file=sys.stderr)
            return 2
        if not index_cache or not index_cache.is_file():
            return 0
        if not args.manifest_id:
            return 0
        try:
            cached = json.loads(index_cache.read_text())
        except Exception:
            return 0
        if cached.get("manifest_id") != args.manifest_id:
            return 0
        bumps = load_bumps(bumps_path)
        for name in advisories_for_bumps(cached, bumps):
            print(name)
        return 0

    root = Path(args.osv_dir)
    bumps_path = Path(args.bumps_file)
    if not root.is_dir():
        print(f"error: osv_dir is not a directory: {root}", file=sys.stderr)
        return 2
    if not bumps_path.is_file():
        print(f"error: bumps_file not found: {bumps_path}", file=sys.stderr)
        return 2

    bumps = load_bumps(bumps_path)
    if not bumps:
        return 0

    index_cache = Path(args.index_cache) if args.index_cache else None
    manifest_id = args.manifest_id or None
    index = load_or_build_index(root, index_cache, manifest_id)

    advisories, parse_errors = load_advisories_for_bumps(root, bumps, index)
    if parse_errors:
        print(f"PARSE_ERRORS: {parse_errors}", file=sys.stderr)

    matches = match_bumps(bumps, advisories)
    for line in matches:
        print(line)
    if not matches:
        print("NO_MATCHING_ADVISORIES", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
