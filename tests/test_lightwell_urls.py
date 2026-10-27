"""Unit tests for Lightwell catalog URL helpers."""

from __future__ import annotations

from lightwell_shared.lightwell_urls import (
    CONTENT_ROOT,
    java_catalog_base,
    maven_metadata_url,
    provenance_bundle_url,
    sbom_url,
)


def test_default_content_root() -> None:
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
