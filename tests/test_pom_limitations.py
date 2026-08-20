"""Characterization tests for POM shapes the regex parser does not fully support."""

from __future__ import annotations

from _paths import FIXTURES
from lightwell_shared.directs_plan import build_direct_plan
from lightwell_shared.pom_lib import parse_pom


def test_dependency_management_entries_are_parsed_as_directs() -> None:
    """Current regex walks every <dependency> block, including BOM entries."""
    pom = parse_pom((FIXTURES / "pom_dependency_management.xml").read_text(encoding="utf-8"))
    gas = {d["ga"] for d in pom["directs"]}
    assert "org.json:json" in gas
    assert "org.example:from-bom" in gas


def test_parent_element_is_ignored() -> None:
    pom = parse_pom((FIXTURES / "pom_with_parent.xml").read_text(encoding="utf-8"))
    gas = {d["ga"] for d in pom["directs"]}
    assert "org.json:json" in gas
    assert "org.example:parent" not in gas


def test_multimodule_parent_pom_does_not_include_child_deps() -> None:
    parent = parse_pom((FIXTURES / "multimodule" / "pom.xml").read_text(encoding="utf-8"))
    child = parse_pom((FIXTURES / "multimodule" / "child" / "pom.xml").read_text(encoding="utf-8"))
    assert "org.json:json" in {d["ga"] for d in parent["directs"]}
    assert "commons-io:commons-io" not in {d["ga"] for d in parent["directs"]}
    assert "commons-io:commons-io" in {d["ga"] for d in child["directs"]}


def test_directs_plan_uses_the_given_pom_only() -> None:
    path = FIXTURES / "multimodule" / "pom.xml"
    plan = build_direct_plan(path.read_text(encoding="utf-8"), path)
    assert all(d["artifactId"] != "commons-io" for d in plan["dependencies"])
