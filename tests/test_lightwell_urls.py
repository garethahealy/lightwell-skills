"""Unit tests for Lightwell demo catalog URL helpers."""

from __future__ import annotations

from lightwell_shared.lightwell_urls import (
    CONTENT_ROOT,
    java_catalog_base,
    maven_metadata_url,
    provenance_bundle_url,
)


def test_demo_content_root() -> None:
    assert "public-lightwell-demo" in CONTENT_ROOT
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
