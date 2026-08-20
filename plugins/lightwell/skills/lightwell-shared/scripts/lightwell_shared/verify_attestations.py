"""Verify Lightwell jars against SLSA provenance (cosign).

Downloads provenance bundles via http_pool (download_http), extracts the
Rekor public key, and runs cosign verify-blob-attestation.

Usage:
  verify_attestations.py remediated org.json json 1.0.0.rhlw-00001
  verify_attestations.py --batch < coords.txt

Never prints credentials. Requires Python 3.14+, cosign, Maven.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from lightwell_shared.download_http import HttpAuthError, download_to_path
from lightwell_shared.lightwell_urls import provenance_bundle_url
from lightwell_shared.mvn_run import maven_binary, repo_root_for, resolve_local_repo
from lightwell_shared.runtime import require_python
from lightwell_shared.thread_jobs import map_threaded


def provenance_cache_root(*, no_cache: bool) -> Path | None:
    if no_cache or os.environ.get("LIGHTWELL_PROVENANCE_NO_CACHE") == "1":
        return None
    override = os.environ.get("LIGHTWELL_PROVENANCE_CACHE_DIR", "").strip()
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_CACHE_HOME", "").strip() or str(Path.home() / ".cache")
    return Path(xdg) / "lightwell-provenance"


def extract_pubkey(bundle: Path, out: Path) -> bool:
    try:
        data = json.loads(bundle.read_text(encoding="utf-8"))
        body_b64 = data["verificationMaterial"]["tlogEntries"][0]["canonicalizedBody"]
        body = json.loads(base64.b64decode(body_b64))
        key_b64 = body["spec"]["signatures"][0]["verifier"]
        pem = base64.b64decode(key_b64)
        out.write_bytes(pem)
    except KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError, OSError:
        return False
    text = out.read_text(encoding="utf-8", errors="replace")
    return "BEGIN PUBLIC KEY" in text and out.stat().st_size > 0


def verify_one(
    catalog: str,
    group_id: str,
    artifact_id: str,
    version: str,
    *,
    local_repo: Path,
    prov_cache: Path | None,
    work_root: Path,
    username: str,
    token: str,
    verbose: bool,
) -> tuple[str, bool]:
    """Return (stdout_line, ok). Raises HttpAuthError on auth failure."""
    gav = f"{group_id}:{artifact_id}:{version}"
    if catalog not in {"remediated", "validated"}:
        return f"FAIL {catalog} {gav} reason=bad-catalog", False

    group_path = group_id.replace(".", "/")
    jar_name = f"{artifact_id}-{version}.jar"
    prov_name = f"{artifact_id}-{version}.provenance.sigstore.json"
    jar = local_repo / group_path / artifact_id / version / jar_name
    work = work_root / f"{catalog}__{group_path.replace('/', '_')}__{artifact_id}__{version}"
    work.mkdir(parents=True, exist_ok=True)
    pubkey = work / "lightwell.pub"

    if not jar.is_file():
        print(f"JAR_MISSING: {jar}", file=sys.stderr)
        return f"FAIL {catalog} {gav} reason=jar-missing", False

    if prov_cache is not None:
        cached_dir = prov_cache / catalog / group_path / artifact_id / version
        cached_dir.mkdir(parents=True, exist_ok=True)
        bundle = cached_dir / prov_name
    else:
        bundle = work / prov_name

    if not bundle.is_file() or bundle.stat().st_size == 0:
        if verbose:
            print(f"Fetching provenance {catalog} {gav}", file=sys.stderr)
        url = provenance_bundle_url(catalog, group_id, artifact_id, version)
        code = download_to_path(url, bundle, username, token)
        if code != 200 or not bundle.is_file() or bundle.stat().st_size == 0:
            print(f"PROVENANCE_MISSING: {catalog} {gav}", file=sys.stderr)
            bundle.unlink(missing_ok=True)
            return f"FAIL {catalog} {gav} reason=provenance-download", False
    elif verbose:
        print(f"Provenance cache hit {catalog} {gav}", file=sys.stderr)

    if not extract_pubkey(bundle, pubkey):
        print(f"KEY_EXTRACT_FAILED: {catalog} {gav}", file=sys.stderr)
        return f"FAIL {catalog} {gav} reason=key-extract", False

    if verbose:
        print(f"cosign verify-blob-attestation {jar_name}", file=sys.stderr)

    proc = subprocess.run(
        [
            "cosign",
            "verify-blob-attestation",
            "--bundle",
            str(bundle),
            "--key",
            str(pubkey),
            "--type",
            "slsaprovenance1",
            "--check-claims=true",
            str(jar),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(f"VERIFY_FAILED: {catalog} {gav}", file=sys.stderr)
        return f"FAIL {catalog} {gav} reason=cosign", False

    return f"OK {catalog} {gav}", True


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
        default=int(os.environ.get("LIGHTWELL_ATTEST_JOBS", "8")),
    )
    parser.add_argument("--settings", default="")
    parser.add_argument("--local-repo", default="")
    parser.add_argument("coords", nargs="*")
    args = parser.parse_args()

    if args.jobs < 1:
        print("error: --jobs must be >= 1", file=sys.stderr)
        return 2

    if not shutil.which("cosign"):
        print("COSIGN_MISSING", file=sys.stderr)
        return 1
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

    prov_cache = provenance_cache_root(no_cache=args.no_cache)
    if prov_cache is not None:
        prov_cache.mkdir(parents=True, exist_ok=True)

    if args.verbose:
        print(f"Local Maven repo: {local_repo}", file=sys.stderr)
        print(
            f"Provenance cache: {prov_cache if prov_cache else 'disabled'}",
            file=sys.stderr,
        )
        print(f"Attest jobs: {args.jobs}", file=sys.stderr)

    with tempfile.TemporaryDirectory(prefix="lightwell-attest-") as tmp:
        work_root = Path(tmp)

        def work(_idx: int, item: tuple[str, str, str, str]) -> tuple[str, bool]:
            catalog, g, a, v = item
            return verify_one(
                catalog,
                g,
                a,
                v,
                local_repo=local_repo,
                prov_cache=prov_cache,
                work_root=work_root,
                username=username,
                token=token,
                verbose=args.verbose,
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

    failed = 0
    for line, ok in results:
        print(line)
        if not ok:
            failed = 1
    return failed


if __name__ == "__main__":
    raise SystemExit(main())
