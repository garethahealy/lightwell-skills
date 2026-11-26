"""Unit tests for Lightwell catalog URL helpers."""

from __future__ import annotations

from lightwell_shared.lightwell_urls import (
    CONTENT_ROOT,
    DEFAULT_API_ROOT,
    DEFAULT_SSO_TOKEN_URL,
    api_root,
    java_catalog_base,
    maven_metadata_url,
    provenance_bundle_url,
    sbom_url,
    sso_token_url,
)


def test_default_api_root(monkeypatch) -> None:
    assert DEFAULT_API_ROOT == "https://console.redhat.com/api/lightwell/v0.1"
    monkeypatch.setenv("LIGHTWELL_API_ROOT", "https://example.test/api/lightwell/v0.1/")
    assert api_root() == "https://example.test/api/lightwell/v0.1"


def test_default_sso_token_url(monkeypatch) -> None:
    assert DEFAULT_SSO_TOKEN_URL == ("https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token")
    monkeypatch.setenv("LIGHTWELL_SSO_TOKEN_URL", "https://example.test/token/")
    assert sso_token_url() == "https://example.test/token/"
    assert CONTENT_ROOT.rstrip("/").endswith("/pulp-content/lightwell")
    assert java_catalog_base("remediated").endswith("/java/remediated/")
    assert java_catalog_base("validated").endswith("/java/validated/")
    assert java_catalog_base("unknown").endswith("/java/remediated/")


def test_maven_metadata_url_group_path() -> None:
    url = maven_metadata_url("validated", "com.fasterxml.jackson.dataformat", "jackson-dataformat-yaml")
    assert url.startswith(CONTENT_ROOT)
    assert url.endswith("/java/validated/com/fasterxml/jackson/dataformat/jackson-dataformat-yaml/maven-metadata.xml")


def test_provenance_url() -> None:
    url = provenance_bundle_url("remediated", "org.json", "json", "1.rhlw-00001")
    assert url.endswith("/json/1.rhlw-00001/json-1.rhlw-00001.provenance.sigstore.json")


def test_sbom_url() -> None:
    url = sbom_url("remediated", "org.json", "json", "1.rhlw-00001")
    assert url.endswith("/json/1.rhlw-00001/json-1.rhlw-00001.cyclonedx.json")
    assert "/java/remediated/org/json/json/1.rhlw-00001/json-1.rhlw-00001.cyclonedx.json" in url
