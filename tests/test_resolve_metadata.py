"""Unit tests for resolve_metadata XML / coord helpers."""

from __future__ import annotations

import pytest

from lightwell_shared.resolve_metadata import (
    MetadataError,
    extract_tag,
    extract_versions,
    highest_rhlw_on_base,
    parse_coords,
    same_base_sidecar_name,
    upstream_base,
)

SAMPLE_XML = """\
<?xml version="1.0"?>
<metadata>
  <latest>20220320.0.0.rhlw-00003</latest>
  <release>20220320.0.0.rhlw-00003</release>
  <versions>
    <version>20220320.0.0.rhlw-00001</version>
    <version>20220320.0.0.rhlw-00003</version>
    <version>20231013.0.0.rhlw-00001</version>
  </versions>
</metadata>
"""


def test_extract_tag_and_versions() -> None:
    assert extract_tag(SAMPLE_XML, "latest") == "20220320.0.0.rhlw-00003"
    assert extract_tag(SAMPLE_XML, "missing") is None
    versions = extract_versions(SAMPLE_XML)
    assert "20220320.0.0.rhlw-00003" in versions
    assert extract_versions("<metadata/>") == []


def test_upstream_base() -> None:
    assert upstream_base("20220320.0.0.rhlw-00003") == "20220320.0.0"
    assert upstream_base("1.2.3") == "1.2.3"


def test_parse_coords() -> None:
    rows = parse_coords(["remediated org.json json"], same_base=False)
    assert rows == [("remediated", "org.json", "json", None)]
    rows = parse_coords(["remediated org.json json 20220320"], same_base=True)
    assert rows[0][3] == "20220320"
    with pytest.raises(MetadataError):
        parse_coords(["central org.json json"], same_base=False)
    assert same_base_sidecar_name("20220320").startswith("same-base-")


def test_highest_rhlw_semver_base_match() -> None:
    versions = [
        "20220320.0.0.rhlw-00001",
        "20220320.0.0.rhlw-00003",
        "20231013.0.0.rhlw-00001",
    ]
    assert highest_rhlw_on_base(versions, "20220320") == "20220320.0.0.rhlw-00003"
    assert highest_rhlw_on_base(versions, "20220320.0.0") == "20220320.0.0.rhlw-00003"
