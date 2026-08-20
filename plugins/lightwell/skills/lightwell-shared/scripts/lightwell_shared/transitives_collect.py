"""Collect phase: remediated transitive actions (PROMOTE/UPDATE/KEEP/DROP)."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from lightwell_shared.mvn_run import run_dependency_tree
from lightwell_shared.pom_lib import (
    ask_reason,
    indexes_by_via_direct,
    is_newer,
    needs_ask,
    versions_by_ga,
)
from lightwell_shared.resolve_metadata import (
    AuthFailedError,
    MetadataError,
    cache_dir_lock,
    cache_fresh,
    default_cache_root,
    default_natural_cache_root,
    natural_coord_cache_dir,
    read_text,
    resolve_payload,
    write_text_atomic,
)
from lightwell_shared.runtime import preflight, print_preflight_errors, require_python
from lightwell_shared.schema import SchemaError, require_schema, stamp
from lightwell_shared.thread_jobs import map_threaded


@dataclass(frozen=True)
class MetaResult:
    ok: bool
    version: str | None = None
    error: str | None = None


def meta_lookup(
    group_id: str,
    artifact_id: str,
    current: str,
    *,
    cache_root: Path | None,
    ttl: int,
    username: str,
    token: str,
) -> MetaResult:
    try:
        version = resolve_payload(
            "remediated",
            group_id,
            artifact_id,
            tag=None,
            same_base_current=current,
            cache_root=cache_root,
            ttl=ttl,
            username=username,
            token=token,
        )
        return MetaResult(ok=True, version=version)
    except AuthFailedError:
        raise
    except MetadataError as exc:
        return MetaResult(ok=False, error=str(exc) if str(exc) else "MISSING")


def natural_ttl() -> int:
    return int(os.environ.get("LIGHTWELL_NATURAL_CACHE_TTL", "3600"))


def load_cached_index(cdir: Path, ttl: int) -> dict[str, str] | None:
    if not cache_fresh(cdir, ttl):
        return None
    idx_text = read_text(cdir / "index.json")
    if idx_text and idx_text.strip():
        try:
            data = json.loads(idx_text)
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items()}
        except json.JSONDecodeError:
            pass
    # Back-compat: full tree.txt from older caches
    tree = read_text(cdir / "tree.txt")
    if tree and tree.strip():
        return versions_by_ga(tree)
    return None


def store_cached_index(cdir: Path, index: dict[str, str]) -> None:
    with cache_dir_lock(cdir):
        write_text_atomic(
            cdir / "index.json",
            json.dumps(index, indent=0, sort_keys=True) + "\n",
        )
        write_text_atomic(cdir / "fetched_at", str(int(time.time())))


def run_combined_parent_tree(
    parents: list[tuple[str, str]],
    settings_rel: str,
    repo_root: Path,
    tmp: Path,
) -> str:
    """One dependency:tree for many parent GAVs (single Maven/mvnd invoke)."""
    deps_xml = []
    for parent_ga, parent_ver in parents:
        parent_g, parent_a = parent_ga.split(":", 1)
        deps_xml.append(
            f"""    <dependency>
      <groupId>{parent_g}</groupId>
      <artifactId>{parent_a}</artifactId>
      <version>{parent_ver}</version>
    </dependency>"""
        )
    pom = tmp / "pom.xml"
    pom.write_text(
        f"""<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>tmp.lightwell</groupId>
  <artifactId>natural-check</artifactId>
  <version>0.0.0</version>
  <dependencies>
{chr(10).join(deps_xml)}
  </dependencies>
</project>
""",
        encoding="utf-8",
    )
    tree_file = tmp / "tree.txt"
    proc = run_dependency_tree(
        repo_root=repo_root,
        settings=settings_rel,
        pom=pom,
        output_file=tree_file,
    )
    if proc.returncode != 0 or not tree_file.is_file() or tree_file.stat().st_size == 0:
        return ""
    return tree_file.read_text(encoding="utf-8")


def resolve_natural_indexes(
    parent_vers: dict[str, str],
    *,
    settings_rel: str,
    repo_root: Path,
    natural_cache: Path | None,
    ttl: int,
) -> dict[str, dict[str, str]]:
    """Return parent_ga -> {dep_ga: version}. Uses cache; one Maven for all misses."""
    indexes: dict[str, dict[str, str]] = {}
    misses: list[tuple[str, str]] = []

    for parent, parent_ver in parent_vers.items():
        parent_g, parent_a = parent.split(":", 1)
        cdir = natural_coord_cache_dir(natural_cache, parent_g, parent_a, parent_ver) if natural_cache else None
        if cdir is not None:
            cached = load_cached_index(cdir, ttl)
            if cached is not None:
                indexes[parent] = cached
                continue
        misses.append((parent, parent_ver))

    if not misses:
        return indexes

    with tempfile.TemporaryDirectory(prefix="lw-nat-") as tmp_s:
        tree = run_combined_parent_tree(misses, settings_rel, repo_root, Path(tmp_s))

    if not tree:
        # Do not cache empties — a failed Maven run must not become false DROPs
        # (gone) for the next hour.
        print("NATURAL_TREE_FAILED", file=sys.stderr)
        return indexes

    by_via = indexes_by_via_direct(tree)
    for parent, parent_ver in misses:
        # Index for this parent: its own node + everything introduced via it
        idx = dict(by_via.get(parent) or {})
        indexes[parent] = idx
        if natural_cache is not None:
            parent_g, parent_a = parent.split(":", 1)
            cdir = natural_coord_cache_dir(natural_cache, parent_g, parent_a, parent_ver)
            store_cached_index(cdir, idx)
    return indexes


def decide_actions(
    plan: dict,
    metadata: dict[str, MetaResult],
    natural: dict[str, dict[str, str]],
    *,
    take_latest: bool = False,
) -> list[dict]:
    rows: list[dict] = []
    promoted_gas = {p["ga"] for p in plan.get("promoted", [])}

    for item in plan.get("promoted", []):
        key = item["ga"]
        cur = item.get("treeVersion") or ""
        via = list(item.get("viaParents") or [])
        g = item.get("groupId") or ""
        meta = metadata.get(key, MetaResult(ok=False, error="MISSING"))
        meta_ok = bool(meta.ok and meta.version and ".rhlw-" in meta.version)
        meta_ver = meta.version or ""

        nat_map = natural.get(key, {})
        if nat_map:
            still = {p: ver for p, ver in nat_map.items() if ver and ver != "ABSENT"}
            checked_via = [p for p in via if p in nat_map]
            if checked_via and not still:
                rows.append(
                    {
                        "action": "DROP",
                        "ga": key,
                        "groupId": item.get("groupId"),
                        "artifactId": item.get("artifactId"),
                        "from": cur,
                        "to": None,
                        "via": via,
                        "reason": "gone",
                    }
                )
                continue
            if still and meta_ok and all(ver == meta_ver for ver in still.values()):
                rows.append(
                    {
                        "action": "DROP",
                        "ga": key,
                        "groupId": item.get("groupId"),
                        "artifactId": item.get("artifactId"),
                        "from": cur,
                        "to": None,
                        "via": sorted(still),
                        "reason": "native",
                    }
                )
                continue
            if still:
                via = sorted(still.keys())

        if meta_ok and meta_ver != cur:
            if not is_newer(meta_ver, cur):
                rows.append(
                    {
                        "action": "KEEP",
                        "ga": key,
                        "groupId": item.get("groupId"),
                        "artifactId": item.get("artifactId"),
                        "from": cur,
                        "to": cur,
                        "via": via,
                        "reason": "candidate-not-newer",
                        "candidate": meta_ver,
                    }
                )
            elif not take_latest and needs_ask(g, cur, meta_ver):
                rows.append(
                    {
                        "action": "ASK",
                        "ga": key,
                        "groupId": item.get("groupId"),
                        "artifactId": item.get("artifactId"),
                        "from": cur,
                        "to": meta_ver,
                        "via": via,
                        "reason": ask_reason(cur, meta_ver),
                        "pending": "UPDATE",
                    }
                )
            else:
                rows.append(
                    {
                        "action": "UPDATE",
                        "ga": key,
                        "groupId": item.get("groupId"),
                        "artifactId": item.get("artifactId"),
                        "from": cur,
                        "to": meta_ver,
                        "via": via,
                        "reason": None,
                    }
                )
        elif meta_ok and meta_ver == cur:
            rows.append(
                {
                    "action": "KEEP",
                    "ga": key,
                    "groupId": item.get("groupId"),
                    "artifactId": item.get("artifactId"),
                    "from": cur,
                    "to": cur,
                    "via": via,
                    "reason": None,
                }
            )
        elif ".rhlw-" in cur:
            rows.append(
                {
                    "action": "KEEP",
                    "ga": key,
                    "groupId": item.get("groupId"),
                    "artifactId": item.get("artifactId"),
                    "from": cur,
                    "to": cur,
                    "via": via,
                    "reason": meta.error,
                }
            )
        else:
            rows.append(
                {
                    "action": "DROP",
                    "ga": key,
                    "groupId": item.get("groupId"),
                    "artifactId": item.get("artifactId"),
                    "from": cur,
                    "to": None,
                    "via": via,
                    "reason": "stale-parent",
                }
            )

    for item in plan.get("candidates", []):
        key = item["ga"]
        if key in promoted_gas:
            continue
        cur = item["treeVersion"]
        via = list(item.get("viaParents") or [])
        g = item.get("groupId") or ""
        meta = metadata.get(key, MetaResult(ok=False, error="MISSING"))
        if not meta.ok or not meta.version or ".rhlw-" not in meta.version:
            continue
        if meta.version == cur:
            continue
        if not is_newer(meta.version, cur):
            continue
        if not take_latest and needs_ask(g, cur, meta.version):
            rows.append(
                {
                    "action": "ASK",
                    "ga": key,
                    "groupId": item.get("groupId"),
                    "artifactId": item.get("artifactId"),
                    "from": cur,
                    "to": meta.version,
                    "via": via,
                    "reason": ask_reason(cur, meta.version),
                    "pending": "PROMOTE",
                }
            )
            continue
        rows.append(
            {
                "action": "PROMOTE",
                "ga": key,
                "groupId": item.get("groupId"),
                "artifactId": item.get("artifactId"),
                "from": cur,
                "to": meta.version,
                "via": via,
                "reason": None,
            }
        )

    return rows


def format_plain(rows: list[dict]) -> str:
    lines: list[str] = []
    for r in rows:
        via_s = ",".join(r.get("via") or []) if r.get("via") else "-"
        action = r["action"]
        key = r["ga"]
        cur = r.get("from") or ""
        if action == "PROMOTE":
            lines.append(f"PROMOTE {key} {cur} -> {r['to']} via {via_s}")
        elif action == "UPDATE":
            lines.append(f"UPDATE {key} {cur} -> {r['to']} via {via_s}")
        elif action == "ASK":
            pending = r.get("pending") or "?"
            lines.append(f"ASK {pending} {key} {cur} -> {r['to']} via {via_s} reason={r.get('reason')}")
        elif action == "KEEP":
            lines.append(f"KEEP {key} {cur} via {via_s}")
        elif action == "DROP":
            reason = r.get("reason") or ""
            lines.append(f"DROP {key} {cur} via {via_s} reason={reason}")
    return "\n".join(lines) + ("\n" if lines else "")


def main() -> int:
    require_python()
    parser = argparse.ArgumentParser(
        description="Collect phase: remediated transitive PROMOTE/UPDATE/KEEP/DROP actions."
    )
    parser.add_argument("--from-plan", required=True)
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument(
        "--skip-natural",
        action="store_true",
        help="Skip natural tree checks for DROP gone/native (faster)",
    )
    parser.add_argument(
        "--take-latest",
        action="store_true",
        help="Apply SemVer ASK rows (major/minor/unsure) without gating",
    )
    parser.add_argument(
        "--ttl",
        type=int,
        default=int(os.environ.get("LIGHTWELL_METADATA_CACHE_TTL", "3600")),
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=int(os.environ.get("LIGHTWELL_METADATA_JOBS", "16")),
    )
    parser.add_argument("-o", "--output", default="", help="Write results to file")
    args = parser.parse_args()

    if not args.skip_natural:
        missing = preflight(maven=True)
        if missing:
            print_preflight_errors(missing)
            return 2

    if args.jobs < 1:
        print("error: --jobs must be >= 1", file=sys.stderr)
        return 2

    plan = json.loads(Path(args.from_plan).read_text(encoding="utf-8"))
    try:
        require_schema(plan, label=args.from_plan)
    except SchemaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    username = os.environ.get("LIGHTWELL_USERNAME", "")
    token = os.environ.get("LIGHTWELL_TOKEN", "")
    if not username or not token:
        print("CREDS_MISSING", file=sys.stderr)
        return 1

    cache_root = default_cache_root(args.no_cache)
    natural_cache = default_natural_cache_root(args.no_cache)
    nat_ttl = natural_ttl()

    queries: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()
    for item in list(plan.get("candidates", [])) + list(plan.get("promoted", [])):
        key = item["ga"]
        if key in seen:
            continue
        seen.add(key)
        ver = item.get("treeVersion") or ""
        if not ver or ver.startswith("${"):
            continue
        g, a = item["groupId"], item["artifactId"]
        queries.append((key, g, a, ver))

    metadata: dict[str, MetaResult] = {}

    def work(_idx: int, q: tuple[str, str, str, str]) -> tuple[str, MetaResult]:
        key, g, a, ver = q
        return key, meta_lookup(
            g,
            a,
            ver,
            cache_root=cache_root,
            ttl=args.ttl,
            username=username,
            token=token,
        )

    if queries:
        try:
            for key, val in map_threaded(
                queries,
                work,
                max_workers=args.jobs,
                cancel_on=AuthFailedError,
            ):
                metadata[key] = val
        except AuthFailedError as exc:
            print(str(exc), file=sys.stderr)
            return 1

    natural: dict[str, dict[str, str]] = {}
    if not args.skip_natural and plan.get("promoted"):
        settings_rel = plan.get("settings") or ".m2/settings.xml"
        repo_root = Path(plan.get("repoRoot") or "")
        if not repo_root.is_dir():
            settings_path = Path(settings_rel)
            if settings_path.is_file():
                repo_root = settings_path.parent.parent
                try:
                    settings_rel = str(settings_path.relative_to(repo_root))
                except ValueError:
                    settings_rel = str(settings_path)
        settings_path = Path(settings_rel) if Path(settings_rel).is_absolute() else repo_root / settings_rel
        directs = plan.get("directs") or {}
        if repo_root.is_dir() and settings_path.is_file():
            parent_vers: dict[str, str] = {}
            promo_parents: list[tuple[str, str]] = []
            for item in plan["promoted"]:
                promo = item["ga"]
                for parent in item.get("viaParents") or []:
                    parent_ver = directs.get(parent, "")
                    if not parent_ver:
                        natural.setdefault(promo, {})[parent] = "ABSENT"
                        continue
                    parent_vers[parent] = parent_ver
                    promo_parents.append((promo, parent))

            parent_indexes = resolve_natural_indexes(
                parent_vers,
                settings_rel=settings_rel,
                repo_root=repo_root,
                natural_cache=natural_cache,
                ttl=nat_ttl,
            )
            for promo, parent in promo_parents:
                idx = parent_indexes.get(parent, {})
                natural.setdefault(promo, {})[parent] = idx.get(promo, "ABSENT")

    rows = decide_actions(plan, metadata, natural, take_latest=args.take_latest)
    out = stamp(
        {
            "pom": plan.get("pom"),
            "repoRoot": plan.get("repoRoot"),
            "settings": plan.get("settings"),
            "treeFile": plan.get("treeFile"),
            "results": rows,
        }
    )
    text = json.dumps(out, indent=2, sort_keys=True) + "\n"

    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    sys.stderr.write(format_plain(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
