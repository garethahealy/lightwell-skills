"""Unit tests for CycloneDX SBOM SHA-256 verification (no network)."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from lightwell_shared.directs_plan import build_direct_plan
from lightwell_shared.download_http import HttpAuthError
from lightwell_shared.lightwell_urls import sbom_url
from lightwell_shared.mvn_run import maven_binary
from lightwell_shared.verify_sboms import load_sbom, plan_coords, sbom_cache_root, verify_one
from lightwell_shared.verify_sboms import main as verify_main

CATALOG = "remediated"
GROUP = "org.json"
ARTIFACT = "json"
VERSION = "1.0.0.rhlw-00001"
GAV = f"{GROUP}:{ARTIFACT}:{VERSION}"
ROOT_REF = f"pkg:maven/{GROUP}/{ARTIFACT}@{VERSION}"


def _put(
    local_repo: Path,
    group: str,
    artifact: str,
    version: str,
    data: bytes,
    *,
    classifier: str = "",
    ext: str = "jar",
) -> str:
    suffix = f"-{classifier}" if classifier else ""
    path = local_repo / group.replace(".", "/") / artifact / version / f"{artifact}-{version}{suffix}.{ext}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def _component(
    group: str,
    artifact: str,
    version: str,
    sha256: str | None,
    *,
    purl: str | None = None,
    ref: str | None = None,
    hashes: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    component_purl = purl if purl is not None else f"pkg:maven/{group}/{artifact}@{version}"
    component: dict[str, object] = {
        "type": "library",
        "bom-ref": ref or component_purl,
        "group": group,
        "name": artifact,
        "version": version,
        "purl": component_purl,
    }
    if hashes is not None:
        component["hashes"] = hashes
    elif sha256 is not None:
        component["hashes"] = [{"alg": "SHA-256", "content": sha256}]
    return component


def _bom(
    components: list[dict[str, object]],
    metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    document: dict[str, object] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": components,
    }
    if metadata is not None:
        document["metadata"] = {"component": metadata}
    return document


def _seed(cache: Path, body: dict[str, object] | str) -> None:
    dest = cache / CATALOG / "org/json" / ARTIFACT / VERSION / f"{ARTIFACT}-{VERSION}.cyclonedx.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    text = body if isinstance(body, str) else json.dumps(body)
    dest.write_text(text, encoding="utf-8")


def _verify(
    local_repo: Path,
    cache: Path,
    allowed: set[tuple[str, str, str]] | None = None,
) -> list[tuple[str, bool]]:
    if allowed is None:
        allowed = {(GROUP, ARTIFACT, VERSION)}
    return verify_one(
        CATALOG,
        GROUP,
        ARTIFACT,
        VERSION,
        local_repo=local_repo,
        sbom_cache=cache,
        work_root=local_repo / "work",
        username="user",
        token="token",
        verbose=False,
        allowed=allowed,
    )


def _row(
    status: str,
    package: str,
    sbom_sha: str = "",
    local_sha: str = "",
    *,
    ok: bool,
) -> tuple[str, bool]:
    return (
        f"| {status} | {CATALOG} {GAV} | {package} | {sbom_sha} | {local_sha} |",
        ok,
    )


def test_sbom_cache_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("LIGHTWELL_SBOM_NO_CACHE", raising=False)
    monkeypatch.delenv("LIGHTWELL_SBOM_CACHE_DIR", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert sbom_cache_root(no_cache=False) == tmp_path / "lightwell-sbom"
    assert sbom_cache_root(no_cache=True) is None
    monkeypatch.setenv("LIGHTWELL_SBOM_NO_CACHE", "1")
    assert sbom_cache_root(no_cache=False) is None
    monkeypatch.delenv("LIGHTWELL_SBOM_NO_CACHE")
    monkeypatch.setenv("LIGHTWELL_SBOM_CACHE_DIR", str(tmp_path / "custom"))
    assert sbom_cache_root(no_cache=False) == tmp_path / "custom"


def test_hash_match_and_cache_hit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    local_repo = tmp_path / "m2"
    subject = _put(local_repo, GROUP, ARTIFACT, VERSION, b"subject-jar")
    dep_sha = _put(local_repo, "commons-io", "commons-io", "2.11.0", b"commons-io-bytes")
    _put(local_repo, "org.transitive", "transitive", "1.0.0", b"transitive")
    direct_ref = "pkg:maven/commons-io/commons-io@2.11.0"
    cache = tmp_path / "cache"
    _seed(
        cache,
        _bom(
            [
                _component("commons-io", "commons-io", "2.11.0", dep_sha, ref=direct_ref),
                _component("org.transitive", "transitive", "1.0.0", "ab" * 20),
            ],
            metadata=_component(GROUP, ARTIFACT, VERSION, subject, ref=ROOT_REF),
        ),
    )

    def fail_download(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("download")

    monkeypatch.setattr("lightwell_shared.verify_sboms.download_to_path", fail_download)
    lines = _verify(local_repo, cache, {(GROUP, ARTIFACT, VERSION), ("commons-io", "commons-io", "2.11.0")})
    assert lines == [
        _row("OK", GAV, subject, subject, ok=True),
        _row("OK", "commons-io:commons-io:2.11.0", dep_sha, dep_sha, ok=True),
    ]


def test_hash_mismatch(tmp_path: Path) -> None:
    local_repo = tmp_path / "m2"
    subject = _put(local_repo, GROUP, ARTIFACT, VERSION, b"subject-jar")
    _put(local_repo, "commons-io", "commons-io", "2.11.0", b"commons-io-bytes")
    direct_ref = "pkg:maven/commons-io/commons-io@2.11.0"
    cache = tmp_path / "cache"
    _seed(
        cache,
        _bom(
            [_component("commons-io", "commons-io", "2.11.0", "a" * 40, ref=direct_ref)],
            metadata=_component(GROUP, ARTIFACT, VERSION, subject, ref=ROOT_REF),
        ),
    )
    local_dep = hashlib.sha256(b"commons-io-bytes").hexdigest()
    assert _verify(local_repo, cache, {(GROUP, ARTIFACT, VERSION), ("commons-io", "commons-io", "2.11.0")}) == [
        _row("OK", GAV, subject, subject, ok=True),
        _row("mismatch", "commons-io:commons-io:2.11.0", "a" * 40, local_dep, ok=False),
    ]


def test_missing_jar_and_sha256_are_skipped(tmp_path: Path) -> None:
    local_repo = tmp_path / "m2"
    subject = _put(local_repo, GROUP, ARTIFACT, VERSION, b"subject-jar")
    missing_ref = "pkg:maven/commons-io/commons-io@2.11.0"
    nosha_ref = "pkg:maven/org.slf4j/slf4j-api@2.0.0"
    _put(local_repo, "org.slf4j", "slf4j-api", "2.0.0", b"slf4j")
    cache = tmp_path / "cache"
    _seed(
        cache,
        _bom(
            [
                _component("commons-io", "commons-io", "2.11.0", "ab" * 20, ref=missing_ref),
                _component("org.slf4j", "slf4j-api", "2.0.0", None, ref=nosha_ref, hashes=[]),
            ],
            metadata=_component(GROUP, ARTIFACT, VERSION, subject, ref=ROOT_REF),
        ),
    )
    allowed = {
        (GROUP, ARTIFACT, VERSION),
        ("commons-io", "commons-io", "2.11.0"),
        ("org.slf4j", "slf4j-api", "2.0.0"),
    }
    assert _verify(local_repo, cache, allowed) == [_row("OK", GAV, subject, subject, ok=True)]


def test_sha1_is_ignored(tmp_path: Path) -> None:
    local_repo = tmp_path / "m2"
    data = b"subject-jar"
    sha256 = _put(local_repo, GROUP, ARTIFACT, VERSION, data)
    cache = tmp_path / "cache"
    _seed(
        cache,
        _bom(
            [],
            metadata=_component(
                GROUP,
                ARTIFACT,
                VERSION,
                None,
                ref=ROOT_REF,
                hashes=[
                    {"alg": "SHA-1", "content": "aa" * 20},
                    {"alg": "SHA-256", "content": sha256.upper()},
                ],
            ),
        ),
    )
    assert _verify(local_repo, cache) == [_row("OK", GAV, sha256, sha256, ok=True)]


def test_not_cyclonedx_and_parse(tmp_path: Path) -> None:
    local_repo = tmp_path / "m2"
    cache = tmp_path / "cache"
    _seed(cache, {"bomFormat": "SPDX", "specVersion": "2.3"})
    sbom_path = cache / CATALOG / "org/json" / ARTIFACT / VERSION / f"{ARTIFACT}-{VERSION}.cyclonedx.json"
    _bom_result, reason = load_sbom(sbom_path)
    assert _bom_result is None
    assert reason == "not-cyclonedx"
    assert _verify(local_repo, cache) == [_row("not-cyclonedx", GAV, ok=False)]

    _seed(cache, "{")
    assert _verify(local_repo, cache) == [_row("sbom-parse", GAV, ok=False)]

    _seed(
        cache,
        _bom([{"type": "library", "name": "leftpad", "version": "1.0.0", "purl": "pkg:npm/leftpad@1.0.0"}]),
    )
    assert _verify(local_repo, cache) == []


def test_download_then_verify(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    local_repo = tmp_path / "m2"
    subject = _put(local_repo, GROUP, ARTIFACT, VERSION, b"subject-jar")
    cache = tmp_path / "cache"
    document = _bom([], metadata=_component(GROUP, ARTIFACT, VERSION, subject, ref=ROOT_REF))
    seen: list[str] = []

    def fake_download(url: str, dest: Path, username: str, token: str) -> int:
        seen.append(url)
        assert username == "user"
        assert token == "token"
        dest.write_text(json.dumps(document), encoding="utf-8")
        return 200

    monkeypatch.setattr("lightwell_shared.verify_sboms.download_to_path", fake_download)
    lines = _verify(local_repo, cache)
    assert lines == [_row("OK", GAV, subject, subject, ok=True)]
    assert seen == [sbom_url(CATALOG, GROUP, ARTIFACT, VERSION)]
    assert seen[0].endswith(f"/{ARTIFACT}-{VERSION}.cyclonedx.json")
    cached = cache / CATALOG / "org/json" / ARTIFACT / VERSION / f"{ARTIFACT}-{VERSION}.cyclonedx.json"
    assert cached.is_file() and cached.stat().st_size > 0


def test_sbom_download_and_missing_local_jar(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    local_repo = tmp_path / "m2"
    cache = tmp_path / "cache"
    monkeypatch.setattr("lightwell_shared.verify_sboms.download_to_path", lambda *_a, **_k: 404)
    assert _verify(local_repo, cache) == [_row("sbom-download", GAV, ok=False)]

    def write_sbom(url: str, dest: Path, username: str, token: str) -> int:
        del url, username, token
        dest.write_text(
            json.dumps(_bom([], metadata=_component(GROUP, ARTIFACT, VERSION, "ab" * 20, ref=ROOT_REF))),
            encoding="utf-8",
        )
        return 200

    monkeypatch.setattr("lightwell_shared.verify_sboms.download_to_path", write_sbom)
    assert _verify(local_repo, cache) == []


def test_auth_error_propagates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    local_repo = tmp_path / "m2"

    def raise_auth(*_args: object, **_kwargs: object) -> int:
        raise HttpAuthError(403)

    monkeypatch.setattr("lightwell_shared.verify_sboms.download_to_path", raise_auth)
    with pytest.raises(HttpAuthError):
        _verify(local_repo, tmp_path / "cache")


def test_plan_coords_match_directs_plan() -> None:
    pom = Path(__file__).resolve().parent / "fixtures" / "sample_pom.xml"
    plan = build_direct_plan(pom.read_text(encoding="utf-8"), pom)
    coords = plan_coords(plan)
    assert ("org.json", "json", "20220320") in coords
    assert ("commons-fileupload", "commons-fileupload", "1.5") in coords
    assert ("commons-io", "commons-io", "2.11.0.rhlw-00001") not in coords
    assert ("junit", "junit", "4.13.2") not in coords


def test_sbom_only_package_is_not_hashed(tmp_path: Path) -> None:
    local_repo = tmp_path / "m2"
    subject = _put(local_repo, GROUP, ARTIFACT, VERSION, b"subject-jar")
    _put(local_repo, "org.transitive", "transitive", "9.9.9", b"not-in-plan")
    cache = tmp_path / "cache"
    _seed(
        cache,
        _bom(
            [_component("org.transitive", "transitive", "9.9.9", "0" * 40)],
            metadata=_component(GROUP, ARTIFACT, VERSION, subject, ref=ROOT_REF),
        ),
    )
    assert _verify(local_repo, cache) == [_row("OK", GAV, subject, subject, ok=True)]


def test_group_name_version_without_purl(tmp_path: Path) -> None:
    local_repo = tmp_path / "m2"
    sha = _put(local_repo, "com.fasterxml.jackson.core", "jackson-databind", "2.14.0", b"databind")
    component = {
        "type": "library",
        "bom-ref": "databind",
        "group": "com.fasterxml.jackson.core",
        "name": "jackson-databind",
        "version": "2.14.0",
        "hashes": [{"alg": "SHA-256", "content": sha}],
    }
    cache = tmp_path / "cache"
    dest = (
        cache
        / CATALOG
        / "com/fasterxml/jackson/core"
        / "jackson-databind"
        / "2.14.0"
        / "jackson-databind-2.14.0.cyclonedx.json"
    )
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        json.dumps({"bomFormat": "CycloneDX", "metadata": {"component": component}, "components": []}),
        encoding="utf-8",
    )
    lines = verify_one(
        CATALOG,
        "com.fasterxml.jackson.core",
        "jackson-databind",
        "2.14.0",
        local_repo=local_repo,
        sbom_cache=cache,
        work_root=tmp_path / "work",
        username="user",
        token="token",
        verbose=False,
        allowed={("com.fasterxml.jackson.core", "jackson-databind", "2.14.0")},
    )
    coord = "com.fasterxml.jackson.core:jackson-databind:2.14.0"
    assert lines == [(f"| OK | remediated {coord} | {coord} | {sha} | {sha} |", True)]


def test_unsafe_version_is_not_a_hash_failure(tmp_path: Path) -> None:
    lines = verify_one(
        CATALOG,
        GROUP,
        ARTIFACT,
        "..",
        local_repo=tmp_path,
        sbom_cache=None,
        work_root=tmp_path / "work",
        username="user",
        token="token",
        verbose=False,
        allowed=set(),
    )
    assert lines == []


def test_main_exit_codes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    local_repo = tmp_path / "m2"
    settings = tmp_path / "settings.xml"
    settings.write_text("<settings/>\n", encoding="utf-8")
    subject = _put(local_repo, GROUP, ARTIFACT, VERSION, b"subject-jar")
    cache = tmp_path / "cache"
    plan = tmp_path / "direct-plan.json"
    plan.write_text(
        json.dumps(
            {
                "dependencies": [
                    {"groupId": GROUP, "artifactId": ARTIFACT, "version": VERSION},
                ]
            }
        ),
        encoding="utf-8",
    )
    _seed(cache, _bom([], metadata=_component(GROUP, ARTIFACT, VERSION, subject, ref=ROOT_REF)))

    maven_binary.cache_clear()
    monkeypatch.setenv("LIGHTWELL_MVN", sys.executable)
    monkeypatch.setenv("LIGHTWELL_USERNAME", "user")
    monkeypatch.setenv("LIGHTWELL_TOKEN", "token")
    monkeypatch.setenv("LIGHTWELL_SBOM_CACHE_DIR", str(cache))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "verify_sboms.py",
            "--settings",
            str(settings),
            "--local-repo",
            str(local_repo),
            "--from-plan",
            str(plan),
            CATALOG,
            GROUP,
            ARTIFACT,
            VERSION,
        ],
    )
    try:
        assert verify_main() == 0
        report = capsys.readouterr().out
        assert report.startswith("| Status | SBOM | Package | SBOM SHA-256 | Local SHA-256 |")
        assert f"| OK | {CATALOG} {GAV} | {GAV} | {subject} | {subject} |" in report

        _seed(cache, _bom([], metadata=_component(GROUP, ARTIFACT, VERSION, "ff" * 20, ref=ROOT_REF)))
        assert verify_main() == 1
        report = capsys.readouterr().out
        local_sha = hashlib.sha256(b"subject-jar").hexdigest()
        assert f"| mismatch | {CATALOG} {GAV} | {GAV} | {'ff' * 20} | {local_sha} |" in report
    finally:
        maven_binary.cache_clear()
