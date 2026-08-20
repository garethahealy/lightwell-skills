"""Unit tests for apply_*_collect_row, set_property_value, prepare_ask_row."""

from __future__ import annotations

import pytest

from _paths import FIXTURES
from lightwell_shared.directs_apply import prepare_ask_row as prepare_ask_row_directs
from lightwell_shared.pom_edit import (
    apply_direct_collect_row,
    apply_transitive_collect_row,
    set_property_value,
)
from lightwell_shared.transitives_apply import prepare_ask_row as prepare_ask_row_transitives


def test_set_property_value() -> None:
    pom = (FIXTURES / "sample_pom.xml").read_text(encoding="utf-8")
    updated = set_property_value(pom, "json.version", "20220320.0.0.rhlw-00003")
    assert "<json.version>20220320.0.0.rhlw-00003</json.version>" in updated
    with pytest.raises(ValueError, match="property not found"):
        set_property_value(pom, "missing.prop", "1")


def test_apply_direct_collect_row_property() -> None:
    pom = (FIXTURES / "sample_pom.xml").read_text(encoding="utf-8")
    out = apply_direct_collect_row(
        pom,
        {
            "groupId": "org.json",
            "artifactId": "json",
            "to": "20220320.0.0.rhlw-00003",
            "catalog": "remediated",
            "property": "json.version",
        },
    )
    assert "20220320.0.0.rhlw-00003" in out


def test_apply_transitive_promote_and_drop() -> None:
    pom = (FIXTURES / "sample_pom.xml").read_text(encoding="utf-8")
    promoted = apply_transitive_collect_row(
        pom,
        {
            "action": "PROMOTE",
            "groupId": "org.yaml",
            "artifactId": "snakeyaml",
            "to": "2.0.rhlw-00001",
            "via": ["com.fasterxml.jackson.dataformat:jackson-dataformat-yaml"],
        },
    )
    assert "snakeyaml" in promoted
    assert "2.0.rhlw-00001" in promoted
    assert "Transitive of com.fasterxml.jackson.dataformat:jackson-dataformat-yaml" in promoted

    dropped = apply_transitive_collect_row(
        promoted,
        {
            "action": "DROP",
            "groupId": "commons-io",
            "artifactId": "commons-io",
            "via": ["commons-fileupload:commons-fileupload"],
        },
    )
    assert "Transitive of commons-fileupload:commons-fileupload" not in dropped


def test_prepare_ask_row_directs() -> None:
    d = prepare_ask_row_directs({"action": "ASK", "to": "1.2.4"})
    assert d["action"] == "UPGRADE"
    assert d["collectAction"] == "ASK"
    assert prepare_ask_row_directs({"action": "UPGRADE"})["action"] == "UPGRADE"


def test_prepare_ask_row_transitives() -> None:
    t = prepare_ask_row_transitives({"action": "ASK", "pending": "PROMOTE", "ga": "g:a"})
    assert t["action"] == "PROMOTE"
    with pytest.raises(ValueError):
        prepare_ask_row_transitives({"action": "ASK", "ga": "g:a"})
