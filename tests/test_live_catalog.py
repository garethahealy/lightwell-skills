"""Live tests against the Lightwell demo catalog and local Maven.

Requires LIGHTWELL_USERNAME / LIGHTWELL_TOKEN, network, and Maven.
Does not mock packages.redhat.com. Provenance/cosign cases stay in this
module but are skipped until the demo catalog publishes bundles (no cosign
install in CI until then).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from _live import (
    DEMO_JSON_A,
    DEMO_JSON_BASE,
    DEMO_JSON_G,
    fixture_pom,
    require_cosign,
    require_lightwell_creds,
    require_mvn,
    write_maven_settings,
)
from lightwell_shared.directs_collect import collect_one
from lightwell_shared.download_http import auth_get, download_to_path
from lightwell_shared.fetch_osv import fetch_osv_lines_for_bumps
from lightwell_shared.lightwell_urls import maven_metadata_url, provenance_bundle_url
from lightwell_shared.mvn_run import run_dependency_tree, run_mvn
from lightwell_shared.pom_lib import indexes_by_via_direct
from lightwell_shared.resolve_metadata import resolve_payload
from lightwell_shared.verify_attestations import extract_pubkey, verify_one

pytestmark = pytest.mark.live

_PROVENANCE_SKIP = pytest.mark.skip(reason="demo catalog does not publish provenance bundles yet")


@pytest.fixture(scope="session")
def lightwell_creds() -> tuple[str, str]:
    return require_lightwell_creds()


@pytest.fixture(scope="session")
def live_work(tmp_path_factory: pytest.TempPathFactory) -> SimpleNamespace:
    root = tmp_path_factory.mktemp("lightwell-live")
    cache = root / "meta-cache"
    cache.mkdir()
    local_repo = root / "m2"
    local_repo.mkdir()
    settings = write_maven_settings(root / "settings.xml", local_repo=local_repo)
    return SimpleNamespace(
        root=root,
        cache=cache,
        local_repo=local_repo,
        settings=settings,
    )


@pytest.fixture(scope="session")
def json_ver(lightwell_creds: tuple[str, str], live_work: SimpleNamespace) -> str:
    user, token = lightwell_creds
    ver = resolve_payload(
        "remediated",
        DEMO_JSON_G,
        DEMO_JSON_A,
        tag=None,
        same_base_current=DEMO_JSON_BASE,
        cache_root=live_work.cache,
        ttl=3600,
        username=user,
        token=token,
    )
    assert ".rhlw-" in ver, ver
    return ver


def test_live_metadata_and_collect(
    lightwell_creds: tuple[str, str],
    live_work: SimpleNamespace,
    json_ver: str,
) -> None:
    user, token = lightwell_creds
    meta_url = maven_metadata_url("remediated", DEMO_JSON_G, DEMO_JSON_A)
    status, body, _headers = auth_get(meta_url, user, token)
    assert status == 200, status
    assert "<version>" in body
    assert json_ver

    row = collect_one(
        {
            "groupId": DEMO_JSON_G,
            "artifactId": DEMO_JSON_A,
            "version": DEMO_JSON_BASE,
            "catalog": "remediated",
            "property": None,
        },
        take_latest=False,
        cache_root=live_work.cache,
        ttl=3600,
        username=user,
        token=token,
    )
    assert row["action"] in {"UPGRADE", "KEEP", "ASK"}, row
    assert row["to"]
    if row["action"] == "UPGRADE":
        assert ".rhlw-" in row["to"]


def test_live_osv(lightwell_creds: tuple[str, str], json_ver: str) -> None:
    user, token = lightwell_creds
    lines = fetch_osv_lines_for_bumps(
        [(DEMO_JSON_G, DEMO_JSON_A, DEMO_JSON_BASE, json_ver)],
        username=user,
        token=token,
    )
    for line in lines:
        parts = line.split("|")
        assert len(parts) >= 5, line
        assert parts[0] == f"{DEMO_JSON_G}:{DEMO_JSON_A}"
        assert parts[3].startswith("fixed=")
        assert parts[4].startswith("osv=")
        assert "public-lightwell-demo" in parts[4]


@_PROVENANCE_SKIP
def test_live_provenance_key(lightwell_creds: tuple[str, str], json_ver: str, live_work: SimpleNamespace) -> None:
    user, token = lightwell_creds
    url = provenance_bundle_url("remediated", DEMO_JSON_G, DEMO_JSON_A, json_ver)
    bundle = live_work.root / f"{DEMO_JSON_A}-{json_ver}.provenance.sigstore.json"
    code = download_to_path(url, bundle, user, token)
    assert code == 200, code
    assert bundle.is_file() and bundle.stat().st_size > 0
    pubkey = live_work.root / "lightwell.pub"
    assert extract_pubkey(bundle, pubkey)


def test_live_maven_tree(live_work: SimpleNamespace) -> None:
    try:
        require_mvn()
    except RuntimeError as exc:
        pytest.skip(str(exc))
    pom = fixture_pom()
    out = live_work.settings.parent / "tree.txt"
    proc = run_dependency_tree(
        repo_root=pom.parent,
        settings=str(live_work.settings),
        pom=pom,
        output_file=out,
    )
    assert proc.returncode == 0, proc.stderr
    text = out.read_text(encoding="utf-8")
    by_via = indexes_by_via_direct(text)
    assert "commons-fileupload:commons-fileupload" in by_via
    assert "commons-io:commons-io" in by_via["commons-fileupload:commons-fileupload"]


@_PROVENANCE_SKIP
def test_live_cosign(
    lightwell_creds: tuple[str, str],
    json_ver: str,
    live_work: SimpleNamespace,
) -> None:
    require_cosign()
    user, token = lightwell_creds
    proc = run_mvn(
        [
            "dependency:get",
            f"-Dartifact={DEMO_JSON_G}:{DEMO_JSON_A}:{json_ver}",
            f"--settings={live_work.settings}",
        ],
        cwd=live_work.settings.parent,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    line, ok = verify_one(
        "remediated",
        DEMO_JSON_G,
        DEMO_JSON_A,
        json_ver,
        local_repo=live_work.local_repo,
        prov_cache=live_work.root / "prov-cache",
        work_root=live_work.root,
        username=user,
        token=token,
        verbose=False,
    )
    assert ok, line
    assert line.startswith("OK remediated"), line
