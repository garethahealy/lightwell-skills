"""Verify Lightwell packages against CycloneDX SBOM SHA-256 hashes.

The upgrade-directs plan selects the packages (direct dependencies from
``pom.xml``). A hash check runs only when that package is also a main JAR
(no classifier) in the downloaded CycloneDX SBOM. A missing local file is
skipped. The only package failure is Status ``mismatch``. Stdout is a
markdown table of the SBOM SHA-256 and the local SHA-256.

Usage:
  verify_sboms.py --from-plan direct-plan.json remediated org.json json 1.0.0.rhlw-00001
  verify_sboms.py --batch --from-plan direct-plan.json < coords.txt

Without ``--from-plan``, the same plan is built from ``--pom`` (default ``pom.xml``).
Never prints credentials. Requires Python 3.14+ and Maven.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote

from lightwell_shared.directs_plan import build_direct_plan
from lightwell_shared.download_http import HttpAuthError, download_to_path
from lightwell_shared.lightwell_urls import sbom_filename, sbom_url
from lightwell_shared.mvn_run import maven_binary, repo_root_for, resolve_local_repo
from lightwell_shared.runtime import require_python
from lightwell_shared.thread_jobs import map_threaded

_CATALOGS = {"remediated", "validated"}


@dataclass(frozen=True)
class SbomPackage:
    group_id: str
    artifact_id: str
    version: str
    ext: str
    classifier: str
    sha256: str

    @property
    def coord(self) -> str:
        return f"{self.group_id}:{self.artifact_id}:{self.version}"

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        return (self.group_id, self.artifact_id, self.version, self.ext, self.classifier)


def sbom_cache_root(*, no_cache: bool) -> Path | None:
    if no_cache or os.environ.get("LIGHTWELL_SBOM_NO_CACHE") == "1":
        return None
    override = os.environ.get("LIGHTWELL_SBOM_CACHE_DIR", "").strip()
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_CACHE_HOME", "").strip() or str(Path.home() / ".cache")
    return Path(xdg) / "lightwell-sbom"


def _safe_segment(value: str) -> bool:
    if not value or value in {".", ".."}:
        return False
    return "/" not in value and "\\" not in value and "\x00" not in value


def _coord_safe(group_id: str, artifact_id: str, version: str) -> bool:
    return all(_safe_segment(part) for part in (group_id, artifact_id, version))


def _gav(group_id: str, artifact_id: str, version: str) -> str:
    return f"{group_id}:{artifact_id}:{version}"


def _qualifier(qualifiers: dict[str, list[str]], name: str) -> str:
    values = qualifiers.get(name) or []
    if not values:
        return ""
    return values[0].strip()


def _identity_from_purl(purl: str) -> tuple[str, str, str, str, str] | None:
    rest = purl.removeprefix("pkg:maven/").split("#", 1)[0]
    path, _, query = rest.partition("?")
    path = unquote(path)
    if "@" not in path:
        return None
    coord, version = path.rsplit("@", 1)
    version = unquote(version).strip()
    if "/" not in coord or not version:
        return None
    group_id, artifact_id = coord.rsplit("/", 1)
    group_id = unquote(group_id).strip()
    artifact_id = unquote(artifact_id).strip()
    if not _coord_safe(group_id, artifact_id, version):
        return None
    qualifiers = parse_qs(query, keep_blank_values=False)
    ext = (_qualifier(qualifiers, "type") or "jar").lower()
    classifier = _qualifier(qualifiers, "classifier")
    if not _safe_segment(ext) or (classifier and not _safe_segment(classifier)):
        return None
    return group_id, artifact_id, version, ext, classifier


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _sha256(component: dict[str, Any]) -> str:
    raw = component.get("hashes")
    if not isinstance(raw, list):
        return ""
    for item in raw:
        if not isinstance(item, dict) or item.get("alg") != "SHA-256":
            continue
        hex_value = _text(item.get("content")).lower()
        if hex_value:
            return hex_value
    return ""


def _identity_from_component(component: dict[str, Any]) -> tuple[str, str, str, str, str] | None:
    purl = component.get("purl")
    if isinstance(purl, str) and purl.startswith("pkg:"):
        if not purl.startswith("pkg:maven/"):
            return None
        return _identity_from_purl(purl)
    group_id = component.get("group")
    artifact_id = component.get("name")
    version = component.get("version")
    if not isinstance(group_id, str) or not isinstance(artifact_id, str) or not isinstance(version, str):
        return None
    if not _coord_safe(group_id, artifact_id, version):
        return None
    return group_id, artifact_id, version, "jar", ""


def _package_from_component(component: dict[str, Any]) -> SbomPackage | None:
    identity = _identity_from_component(component)
    if identity is None:
        return None
    group_id, artifact_id, version, ext, classifier = identity
    return SbomPackage(
        group_id=group_id,
        artifact_id=artifact_id,
        version=version,
        ext=ext,
        classifier=classifier,
        sha256=_sha256(component),
    )


def _component_dicts(bom: dict[str, Any]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    metadata = bom.get("metadata")
    if isinstance(metadata, dict):
        component = metadata.get("component")
        if isinstance(component, dict):
            found.append(component)
    components = bom.get("components")
    if isinstance(components, list):
        for item in components:
            if isinstance(item, dict):
                found.append(item)
    return found


def sbom_jar_packages(bom: dict[str, Any]) -> list[SbomPackage]:
    """Maven JARs from ``metadata.component`` and ``components``, main artifact only."""
    seen: set[tuple[str, str, str, str, str]] = set()
    packages: list[SbomPackage] = []
    for component in _component_dicts(bom):
        package = _package_from_component(component)
        if package is None or package.ext != "jar" or package.classifier or package.key in seen:
            continue
        seen.add(package.key)
        packages.append(package)
    return packages


def plan_coords(plan: dict[str, Any]) -> set[tuple[str, str, str]]:
    """``(groupId, artifactId, version)`` from an upgrade-directs plan ``dependencies`` list."""
    dependencies = plan.get("dependencies")
    if not isinstance(dependencies, list):
        return set()
    found: set[tuple[str, str, str]] = set()
    for dep in dependencies:
        if not isinstance(dep, dict):
            continue
        group = dep.get("groupId")
        artifact = dep.get("artifactId")
        version = dep.get("version")
        if isinstance(group, str) and isinstance(artifact, str) and isinstance(version, str):
            group, artifact, version = group.strip(), artifact.strip(), version.strip()
            if group and artifact and version:
                found.add((group, artifact, version))
    return found


def plan_hits(bom: dict[str, Any], coords: set[tuple[str, str, str]]) -> list[SbomPackage]:
    """JARs that appear in both the directs plan and the SBOM."""
    return [
        package
        for package in sbom_jar_packages(bom)
        if (package.group_id, package.artifact_id, package.version) in coords
    ]


def load_sbom(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    """Return ``(bom, None)`` or ``(None, reason)`` (``sbom-parse`` or ``not-cyclonedx``)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError, UnicodeError, json.JSONDecodeError:
        return None, "sbom-parse"
    if not isinstance(data, dict):
        return None, "sbom-parse"
    if data.get("bomFormat") != "CycloneDX":
        return None, "not-cyclonedx"
    return data, None


def maven_artifact_path(local_repo: Path, package: SbomPackage) -> Path | None:
    """Path of the package file under ``local_repo``, or None if it would escape."""
    segments = [package.group_id, package.artifact_id, package.version, package.ext]
    if package.classifier:
        segments.append(package.classifier)
    if any(not _safe_segment(part) for part in segments):
        return None
    suffix = f"-{package.classifier}" if package.classifier else ""
    filename = f"{package.artifact_id}-{package.version}{suffix}.{package.ext}"
    path = local_repo / package.group_id.replace(".", "/") / package.artifact_id / package.version / filename
    try:
        path.resolve().relative_to(local_repo.resolve())
    except ValueError:
        return None
    return path


def file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def sha256_status(local_repo: Path, package: SbomPackage) -> tuple[str, str] | None:
    """Return ``(ok|mismatch, local SHA-256)``, or None when the file or hash is absent."""
    if not package.sha256:
        return None
    path = maven_artifact_path(local_repo, package)
    if path is None or not path.is_file():
        return None
    local_sha = file_sha256(path)
    status = "ok" if local_sha == package.sha256 else "mismatch"
    return status, local_sha


def _md_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _table_row(status: str, sbom: str, package: str, sbom_sha: str, local_sha: str, *, ok: bool) -> tuple[str, bool]:
    cells = (status, sbom, package, sbom_sha, local_sha)
    return "| " + " | ".join(_md_cell(cell) for cell in cells) + " |", ok


REPORT_HEADER = (
    "| Status | SBOM | Package | SBOM SHA-256 | Local SHA-256 |",
    "| ------ | ---- | ------- | ------------ | ------------- |",
)


def format_report(rows: list[tuple[str, bool]]) -> str:
    """Markdown table of check rows, or a one-line note when nothing was checked."""
    if not rows:
        return "No packages checked.\n"
    body = [line for line, _ok in rows]
    return "\n".join((*REPORT_HEADER, *body)) + "\n"


def _fail_gav(catalog: str, group_id: str, artifact_id: str, version: str, reason: str) -> tuple[str, bool]:
    gav = _gav(group_id, artifact_id, version)
    return _table_row(reason, f"{catalog} {gav}", gav, "", "", ok=False)


def _pkg_line(
    catalog: str,
    group_id: str,
    artifact_id: str,
    version: str,
    package: SbomPackage,
    local_sha: str,
    reason: str | None,
) -> tuple[str, bool]:
    status = "OK" if reason is None else reason
    return _table_row(
        status,
        f"{catalog} {_gav(group_id, artifact_id, version)}",
        package.coord,
        package.sha256,
        local_sha,
        ok=reason is None,
    )


def _checked(
    catalog: str,
    group_id: str,
    artifact_id: str,
    version: str,
    packages: list[SbomPackage],
    local_repo: Path,
) -> list[tuple[str, bool]]:
    lines: list[tuple[str, bool]] = []
    for package in packages:
        compared = sha256_status(local_repo, package)
        if compared is None:
            continue
        status, local_sha = compared
        reason = None if status == "ok" else status
        lines.append(_pkg_line(catalog, group_id, artifact_id, version, package, local_sha, reason))
    return lines


def verify_one(
    catalog: str,
    group_id: str,
    artifact_id: str,
    version: str,
    *,
    local_repo: Path,
    sbom_cache: Path | None,
    work_root: Path,
    username: str,
    token: str,
    verbose: bool,
    allowed: set[tuple[str, str, str]],
) -> list[tuple[str, bool]]:
    """Return table rows for one SBOM coordinate. Raises HttpAuthError on auth failure."""
    gav = _gav(group_id, artifact_id, version)
    if catalog not in _CATALOGS:
        return [_table_row("bad-catalog", f"{catalog} {gav}", gav, "", "", ok=False)]
    if not _coord_safe(group_id, artifact_id, version):
        return []

    group_path = group_id.replace(".", "/")
    sbom_name = sbom_filename(artifact_id, version)

    if sbom_cache is not None:
        cached_dir = sbom_cache / catalog / group_path / artifact_id / version
        cached_dir.mkdir(parents=True, exist_ok=True)
        sbom_path = cached_dir / sbom_name
    else:
        work_name = f"{catalog}__{group_path.replace('/', '_')}__{artifact_id}__{version}"
        sbom_path = work_root / work_name / sbom_name
        sbom_path.parent.mkdir(parents=True, exist_ok=True)

    if not sbom_path.is_file() or sbom_path.stat().st_size == 0:
        if verbose:
            print(f"Fetching SBOM {catalog} {gav}", file=sys.stderr)
        url = sbom_url(catalog, group_id, artifact_id, version)
        code = download_to_path(url, sbom_path, username, token)
        if code != 200 or not sbom_path.is_file() or sbom_path.stat().st_size == 0:
            print(f"SBOM_MISSING: {catalog} {gav}", file=sys.stderr)
            sbom_path.unlink(missing_ok=True)
            return [_fail_gav(catalog, group_id, artifact_id, version, "sbom-download")]
    elif verbose:
        print(f"SBOM cache hit {catalog} {gav}", file=sys.stderr)

    bom, err = load_sbom(sbom_path)
    if err is not None or bom is None:
        reason = err or "sbom-parse"
        print(f"SBOM_INVALID: {catalog} {gav} reason={reason}", file=sys.stderr)
        return [_fail_gav(catalog, group_id, artifact_id, version, reason)]

    return _checked(catalog, group_id, artifact_id, version, plan_hits(bom, allowed), local_repo)


def load_direct_plan(path: Path) -> dict[str, Any] | None:
    """Read an upgrade-directs plan JSON file."""
    if not path.is_file():
        print(f"error: plan not found: {path}", file=sys.stderr)
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError, UnicodeError, json.JSONDecodeError:
        print(f"error: plan is not JSON: {path}", file=sys.stderr)
        return None
    if not isinstance(data, dict):
        print(f"error: plan is not a JSON object: {path}", file=sys.stderr)
        return None
    return data


def parse_coords(args: argparse.Namespace) -> list[tuple[str, str, str, str]]:
    coords: list[tuple[str, str, str, str]] = []
    if args.batch:
        if args.coords:
            raise SystemExit("error: --batch reads coordinates from stdin; unexpected positionals")
        for line in sys.stdin:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 4:
                raise SystemExit(f"error: batch line must be: catalog groupId artifactId version (got: {line})")
            coords.append((parts[0], parts[1], parts[2], parts[3]))
    else:
        if len(args.coords) < 4 or len(args.coords) % 4 != 0:
            raise SystemExit("error: expected catalog groupId artifactId version (repeatable sets of four)")
        raw = list(args.coords)
        for i in range(0, len(raw), 4):
            coords.append((raw[i], raw[i + 1], raw[i + 2], raw[i + 3]))
    if not coords:
        raise SystemExit("error: no coordinates to verify")
    return coords


def main() -> int:
    require_python()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--batch", action="store_true")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument(
        "--jobs",
        type=int,
        default=int(os.environ.get("LIGHTWELL_SBOM_JOBS", "8")),
    )
    parser.add_argument("--settings", default="")
    parser.add_argument("--local-repo", default="")
    parser.add_argument("--pom", default="pom.xml")
    parser.add_argument(
        "--from-plan",
        default="",
        help="upgrade-directs plan JSON (default: build that plan from --pom)",
    )
    parser.add_argument("coords", nargs="*")
    args = parser.parse_args()

    if args.jobs < 1:
        print("error: --jobs must be >= 1", file=sys.stderr)
        return 2

    if not shutil.which(maven_binary()):
        print(f"error: mvn or mvnd is required (got: {maven_binary()})", file=sys.stderr)
        return 1

    username = os.environ.get("LIGHTWELL_USERNAME", "")
    token = os.environ.get("LIGHTWELL_TOKEN", "")
    if not username or not token:
        print("CREDS_MISSING", file=sys.stderr)
        return 1

    try:
        coords = parse_coords(args)
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        return 2

    repo_root = repo_root_for(Path.cwd())
    settings = args.settings or str(repo_root / ".m2" / "settings.xml")
    settings_path = Path(settings)
    if not settings_path.is_file():
        print(f"error: Maven settings not found: {settings}", file=sys.stderr)
        return 2
    settings_arg = (
        ".m2/settings.xml"
        if settings_path.resolve() == (repo_root / ".m2" / "settings.xml").resolve()
        else str(settings_path)
    )

    if args.local_repo:
        local_repo = Path(args.local_repo)
    else:
        resolved = resolve_local_repo(repo_root, settings_arg)
        if resolved is None:
            print("LOCAL_REPO_FAILED", file=sys.stderr)
            return 1
        local_repo = resolved
    if not local_repo.is_dir():
        print(f"LOCAL_REPO_FAILED: not a directory: {local_repo}", file=sys.stderr)
        return 1

    if args.from_plan:
        plan = load_direct_plan(Path(args.from_plan))
        if plan is None:
            return 2
    else:
        pom_path = Path(args.pom)
        if not pom_path.is_file():
            print(f"error: pom not found: {pom_path}", file=sys.stderr)
            return 2
        plan = build_direct_plan(pom_path.read_text(encoding="utf-8"), pom_path)
    allowed = plan_coords(plan)

    sbom_cache = sbom_cache_root(no_cache=args.no_cache)
    if sbom_cache is not None:
        sbom_cache.mkdir(parents=True, exist_ok=True)

    if args.verbose:
        print(f"Local Maven repo: {local_repo}", file=sys.stderr)
        print(
            f"SBOM cache: {sbom_cache if sbom_cache else 'disabled'}",
            file=sys.stderr,
        )
        print(f"Direct plan packages: {len(allowed)}", file=sys.stderr)
        print(f"SBOM jobs: {args.jobs}", file=sys.stderr)

    with tempfile.TemporaryDirectory(prefix="lightwell-sbom-") as tmp:
        work_root = Path(tmp)

        def work(_idx: int, item: tuple[str, str, str, str]) -> list[tuple[str, bool]]:
            catalog, group, artifact, ver = item
            return verify_one(
                catalog,
                group,
                artifact,
                ver,
                local_repo=local_repo,
                sbom_cache=sbom_cache,
                work_root=work_root,
                username=username,
                token=token,
                verbose=args.verbose,
                allowed=allowed,
            )

        try:
            results = map_threaded(
                coords,
                work,
                max_workers=args.jobs,
                cancel_on=HttpAuthError,
            )
        except HttpAuthError as exc:
            print(str(exc), file=sys.stderr)
            return 1

    rows: list[tuple[str, bool]] = [row for batch in results for row in batch]
    sys.stdout.write(format_report(rows))
    return 1 if any(not ok for _line, ok in rows) else 0


if __name__ == "__main__":
    raise SystemExit(main())
