"""Unit tests for coords_from_apply / coords_from_pom."""

from __future__ import annotations

from _paths import FIXTURES
from lightwell_shared.coords_from_apply import rows_to_coords
from lightwell_shared.coords_from_pom import coords_from_pom


def test_rows_to_coords_skips_drop_and_unknown() -> None:
    apply = {
        "applied": [
            {
                "groupId": "org.json",
                "artifactId": "json",
                "to": "20220320.0.0.rhlw-00003",
                "action": "UPGRADE",
                "catalog": "remediated",
            },
            {
                "groupId": "commons-io",
                "artifactId": "commons-io",
                "to": "2.11.0.rhlw-00001",
                "action": "DROP",
                "catalog": "remediated",
            },
            {
                "groupId": "org.example",
                "artifactId": "plain",
                "to": "1.0.0",
                "action": "UPGRADE",
                "catalog": "central",
            },
            {
                "groupId": "org.example",
                "artifactId": "rhlw-unknown-catalog",
                "to": "1.0.0.rhlw-00001",
                "action": "PROMOTE",
                "catalog": "other",
            },
        ]
    }
    rows = rows_to_coords(apply)
    assert ("remediated", "org.json", "json", "20220320.0.0.rhlw-00003") in rows
    assert all(r[1] != "commons-io" for r in rows)
    assert all(r[2] != "plain" for r in rows)
    assert (
        "remediated",
        "org.example",
        "rhlw-unknown-catalog",
        "1.0.0.rhlw-00001",
    ) in rows


def test_rows_to_coords_dedupes() -> None:
    apply = {
        "applied": [
            {
                "groupId": "g",
                "artifactId": "a",
                "to": "1.0.0.rhlw-00001",
                "catalog": "remediated",
                "action": "UPDATE",
            },
            {
                "groupId": "g",
                "artifactId": "a",
                "to": "1.0.0.rhlw-00001",
                "catalog": "remediated",
                "action": "UPDATE",
            },
        ]
    }
    assert len(rows_to_coords(apply)) == 1


def test_coords_from_pom_lightwell_only() -> None:
    text = (FIXTURES / "sample_pom.xml").read_text(encoding="utf-8")
    rows = coords_from_pom(text)
    catalogs = {(c, g, a) for c, g, a, _v in rows}
    assert ("remediated", "commons-io", "commons-io") in catalogs
    assert (
        "validated",
        "com.fasterxml.jackson.dataformat",
        "jackson-dataformat-yaml",
    ) in catalogs
    assert not any(a == "json" and c == "remediated" for c, _g, a, _v in rows)
    assert not any(a == "plain" for _c, _g, a, _v in rows)
    assert not any(a == "junit" for _c, _g, a, _v in rows)
