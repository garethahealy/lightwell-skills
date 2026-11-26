"""Unit tests for the Lightwell API client and metadata adapter. No network."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lightwell_shared.directs_collect import try_resolve
from lightwell_shared.download_http import HttpAuthError
from lightwell_shared.lightwell_api import (
    ApiError,
    TermsRequiredError,
    clear_state,
    flatten_published_versions,
    java_package_metadata_xml,
    list_advisories,
    render_metadata_xml,
    select_catalog_repository,
    set_transport,
)
from lightwell_shared.lightwell_urls import api_root, java_catalog_base
from lightwell_shared.resolve_metadata import (
    AuthFailedError,
    MetadataError,
    _coords_from_metadata_url,
    _memo,
    extract_tag,
    extract_versions,
    fetch_metadata_http,
    maven_metadata_url,
    resolve_payload,
)

_USER = "user"
_TOKEN = "tok"


@pytest.fixture(autouse=True)
def _isolate() -> None:
    clear_state()
    _memo.clear()
    yield
    clear_state()
    _memo.clear()


def _repo(catalog: str = "remediated") -> dict:
    return {
        "uuid": f"uuid-{catalog}",
        "name": f"lightwell-java-{catalog}",
        "published_distribution_url": java_catalog_base(catalog),
    }


def _versions_body() -> dict:
    return {
        "group": "org.json",
        "name": "json",
        "versions": [
            {
                "version": "20220320",
                "upstream_version": "not-a-published-coordinate",
                "builds": [
                    {"version": "20220320.0.0.rhlw-00001", "release": "baseline"},
                    {"version": "20220320.0.0.rhlw-00003", "release": "hotfix"},
                ],
            }
        ],
    }


def test_metadata_url_coords_round_trip() -> None:
    url = maven_metadata_url("validated", "com.fasterxml.jackson.dataformat", "jackson-dataformat-yaml")
    assert _coords_from_metadata_url(url) == (
        "validated",
        "com.fasterxml.jackson.dataformat",
        "jackson-dataformat-yaml",
    )


def test_flatten_keeps_published_versions_only() -> None:
    versions = flatten_published_versions(_versions_body())
    assert versions == [
        "20220320",
        "20220320.0.0.rhlw-00001",
        "20220320.0.0.rhlw-00003",
    ]


def test_render_metadata_sets_latest_and_release() -> None:
    xml = render_metadata_xml(["1.2.4", "1.2.5-SNAPSHOT"])
    assert extract_tag(xml, "latest") == "1.2.5-SNAPSHOT"
    assert extract_tag(xml, "release") == "1.2.4"
    assert extract_versions(xml) == ["1.2.4", "1.2.5-SNAPSHOT"]


def test_select_catalog_repository_requires_one_match() -> None:
    repo = _repo()
    assert select_catalog_repository([repo], "remediated")["uuid"] == "uuid-remediated"
    with pytest.raises(ApiError, match="0 maven repositories"):
        select_catalog_repository([], "remediated")
    with pytest.raises(ApiError, match="2 maven repositories"):
        select_catalog_repository([repo, dict(repo)], "remediated")


def test_auth_probe_locks_basic_after_bearer_denial() -> None:
    seen: list[str] = []

    def transport(url: str, headers: dict[str, str]) -> tuple[int, str, dict[str, str]]:
        seen.append(headers["Authorization"])
        if url.endswith("/terms/required"):
            if headers["Authorization"].startswith("Bearer "):
                return 401, "", {}
            return 200, '{"required": false}', {}
        if "java_packages/org.json/json" in url:
            return 200, json.dumps(_versions_body()), {}
        if "content_type=maven" in url:
            return 200, json.dumps({"data": [_repo()], "meta": {"count": 1}}), {}
        raise AssertionError(url)

    set_transport(transport)
    xml = java_package_metadata_xml("remediated", "org.json", "json", _USER, _TOKEN)
    assert extract_tag(xml, "latest") == "20220320.0.0.rhlw-00003"
    assert seen[0].startswith("Bearer ")
    assert seen[1].startswith("Basic ")
    assert all(item.startswith("Basic ") for item in seen[2:])


def test_terms_required_stops() -> None:
    def transport(url: str, headers: dict[str, str]) -> tuple[int, str, dict[str, str]]:
        del url, headers
        return 200, '{"required": true}', {}

    set_transport(transport)
    with pytest.raises(TermsRequiredError, match="TERMS_REQUIRED"):
        java_package_metadata_xml("remediated", "org.json", "json", _USER, _TOKEN)


def test_auth_failure_when_neither_scheme_is_accepted() -> None:
    def transport(url: str, headers: dict[str, str]) -> tuple[int, str, dict[str, str]]:
        del url, headers
        return 403, "", {}

    set_transport(transport)
    with pytest.raises(HttpAuthError) as raised:
        java_package_metadata_xml("remediated", "org.json", "json", _USER, _TOKEN)
    assert raised.value.code == 403


def test_repository_paging_and_content_type_fallback() -> None:
    calls: list[str] = []

    def transport(url: str, headers: dict[str, str]) -> tuple[int, str, dict[str, str]]:
        del headers
        calls.append(url)
        if url.endswith("/terms/required"):
            return 200, '{"required": false}', {}
        if "/repositories/" in url and "java_packages" in url:
            return 200, json.dumps(_versions_body()), {}
        if "content_type=maven" in url:
            return 200, json.dumps({"data": [], "meta": {"count": 0}}), {}
        if "/repositories?" in url:
            page = [_repo("validated")] if "offset=0" in url else []
            return 200, json.dumps({"data": page, "meta": {"count": 1}}), {}
        raise AssertionError(url)

    set_transport(transport)
    xml = java_package_metadata_xml("validated", "org.json", "json", _USER, _TOKEN)
    assert "20220320.0.0.rhlw-00003" in xml
    assert any("content_type=maven" in url for url in calls)
    assert any("/repositories?" in url and "content_type=maven" not in url for url in calls)
    assert any("java_packages/org.json/json" in url for url in calls)


def test_repository_list_reads_every_page() -> None:
    def transport(url: str, headers: dict[str, str]) -> tuple[int, str, dict[str, str]]:
        del headers
        if url.endswith("/terms/required"):
            return 200, '{"required": false}', {}
        if "java_packages" in url:
            return 200, json.dumps(_versions_body()), {}
        if "offset=0" in url:
            filler = [{"uuid": f"u{i}", "url": "https://example.test/none"} for i in range(100)]
            return 200, json.dumps({"data": filler, "meta": {"count": 101}}), {}
        if "offset=100" in url:
            return 200, json.dumps({"data": [_repo()], "meta": {"count": 101}}), {}
        raise AssertionError(url)

    set_transport(transport)
    xml = java_package_metadata_xml("remediated", "org.json", "json", _USER, _TOKEN)
    assert "20220320.0.0.rhlw-00003" in xml


def test_advisory_query_omits_narrowing_filters() -> None:
    seen: list[str] = []

    def transport(url: str, headers: dict[str, str]) -> tuple[int, str, dict[str, str]]:
        del headers
        seen.append(url)
        if url.endswith("/terms/required"):
            return 200, '{"required": false}', {}
        if "content_type=maven" in url:
            return 200, json.dumps({"data": [_repo()], "meta": {"count": 1}}), {}
        if url.startswith(f"{api_root()}/advisories?"):
            return 200, json.dumps({"data": [], "meta": {"count": 0}}), {}
        raise AssertionError(url)

    set_transport(transport)
    assert list_advisories("org.json", "json", _USER, _TOKEN) == []
    query = next(url for url in seen if "/advisories?" in url)
    assert "package_name=org.json%3Ajson" in query
    assert "repository=lightwell-java-remediated" in query
    assert "package_version=" not in query
    assert "cve_id=" not in query
    assert "latest_release=" not in query


def test_resolve_payload_same_base_and_latest(tmp_path: Path) -> None:
    def transport(url: str, headers: dict[str, str]) -> tuple[int, str, dict[str, str]]:
        del headers
        if url.endswith("/terms/required"):
            return 200, '{"required": false}', {}
        if "content_type=maven" in url:
            return 200, json.dumps({"data": [_repo()], "meta": {"count": 1}}), {}
        if "java_packages/org.json/json" in url:
            return 200, json.dumps(_versions_body()), {}
        raise AssertionError(url)

    set_transport(transport)
    same = resolve_payload(
        "remediated",
        "org.json",
        "json",
        tag=None,
        same_base_current="20220320",
        cache_root=tmp_path,
        ttl=3600,
        username=_USER,
        token=_TOKEN,
    )
    assert same == "20220320.0.0.rhlw-00003"
    _memo.clear()
    latest = resolve_payload(
        "remediated",
        "org.json",
        "json",
        tag="latest",
        same_base_current=None,
        cache_root=tmp_path / "latest",
        ttl=3600,
        username=_USER,
        token=_TOKEN,
    )
    assert latest == "20220320.0.0.rhlw-00003"


def test_fetch_metadata_http_maps_404_and_auth(tmp_path: Path) -> None:
    def missing(url: str, headers: dict[str, str]) -> tuple[int, str, dict[str, str]]:
        del headers
        if url.endswith("/terms/required"):
            return 200, '{"required": false}', {}
        if "content_type=maven" in url:
            return 200, json.dumps({"data": [_repo()], "meta": {"count": 1}}), {}
        if "java_packages" in url:
            return 404, "", {}
        raise AssertionError(url)

    set_transport(missing)
    code, body, _headers = fetch_metadata_http(
        maven_metadata_url("remediated", "org.json", "json"),
        _USER,
        _TOKEN,
        None,
    )
    assert code == 404
    assert body == ""

    clear_state()

    def denied(url: str, headers: dict[str, str]) -> tuple[int, str, dict[str, str]]:
        del url, headers
        return 401, "", {}

    set_transport(denied)
    with pytest.raises(AuthFailedError):
        resolve_payload(
            "remediated",
            "org.json",
            "json",
            tag="latest",
            same_base_current=None,
            cache_root=tmp_path,
            ttl=0,
            username=_USER,
            token=_TOKEN,
        )


def test_try_resolve_does_not_swallow_terms() -> None:
    def transport(url: str, headers: dict[str, str]) -> tuple[int, str, dict[str, str]]:
        del url, headers
        return 428, "", {}

    set_transport(transport)
    with pytest.raises(TermsRequiredError):
        try_resolve(
            "remediated",
            "org.json",
            "json",
            tag="latest",
            same_base_current=None,
            cache_root=None,
            ttl=0,
            username=_USER,
            token=_TOKEN,
        )


def test_empty_version_list_is_metadata_empty() -> None:
    def transport(url: str, headers: dict[str, str]) -> tuple[int, str, dict[str, str]]:
        del headers
        if url.endswith("/terms/required"):
            return 200, '{"required": false}', {}
        if "content_type=maven" in url:
            return 200, json.dumps({"data": [_repo()], "meta": {"count": 1}}), {}
        if "java_packages" in url:
            return 200, json.dumps({"group": "org.json", "name": "json", "versions": []}), {}
        raise AssertionError(url)

    set_transport(transport)
    with pytest.raises(MetadataError, match="METADATA_EMPTY"):
        resolve_payload(
            "remediated",
            "org.json",
            "json",
            tag="latest",
            same_base_current=None,
            cache_root=None,
            ttl=0,
            username=_USER,
            token=_TOKEN,
        )
