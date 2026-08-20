"""Unit tests for pom_lib parse_pom / catalog / version property resolution."""

from __future__ import annotations

from _paths import FIXTURES
from lightwell_shared.pom_lib import (
    infer_catalog,
    parse_pom,
    parse_properties,
    parse_tree,
    parse_via_list,
    resolve_version,
)


def test_infer_catalog() -> None:
    rem = "https://packages.redhat.com/api/pulp-content/public-lightwell-demo/java/remediated/"
    val = "https://packages.redhat.com/api/pulp-content/public-lightwell-demo/java/validated/"
    assert infer_catalog("1.0.0", rem) == "remediated"
    assert infer_catalog("1.0.0", val) == "validated"
    assert infer_catalog("1.0.0.rhlw-00001", None) == "remediated"
    assert infer_catalog("1.0.0", None) == "unknown"


def test_resolve_version_and_properties() -> None:
    pom = (FIXTURES / "sample_pom.xml").read_text(encoding="utf-8")
    props = parse_properties(pom)
    assert props["json.version"] == "20220320"
    assert resolve_version("${json.version}", props) == ("20220320", "json.version")
    assert resolve_version("1.2.3", props) == ("1.2.3", None)
    assert resolve_version("${missing}", props) == ("${missing}", "missing")


def test_parse_via_list() -> None:
    assert parse_via_list("a:b, c:d") == ["a:b", "c:d"]
    assert parse_via_list("not-a-ga, g:a") == ["g:a"]


def test_parse_pom_directs_promoted_scopes() -> None:
    pom = parse_pom((FIXTURES / "sample_pom.xml").read_text(encoding="utf-8"))
    directs = {d["ga"]: d for d in pom["directs"]}
    promoted = {p["ga"]: p for p in pom["promoted"]}
    assert "org.json:json" in directs
    assert directs["org.json:json"]["version"] == "20220320"
    assert directs["org.json:json"]["property"] == "json.version"
    assert directs["org.json:json"]["catalog"] == "remediated"
    assert "commons-io:commons-io" in promoted
    assert promoted["commons-io:commons-io"]["via"] == ["commons-fileupload:commons-fileupload"]
    yaml = directs["com.fasterxml.jackson.dataformat:jackson-dataformat-yaml"]
    assert yaml["catalog"] == "validated"
    assert yaml["source"]
    assert "junit:junit" not in directs
    assert pom["exclusions"]["commons-fileupload:commons-fileupload"] == ["commons-io:commons-io"]
    assert directs["org.example:plain"]["catalog"] == "unknown"


def test_parse_tree_skips_test_scope() -> None:
    tree = (FIXTURES / "tree.txt").read_text(encoding="utf-8")
    nodes = parse_tree(tree)
    gas = {(n["ga"], n["scope"]) for n in nodes}
    assert ("junit:junit", "test") in gas
    depths = {n["ga"]: n["depth"] for n in nodes}
    assert depths["commons-io:commons-io"] == 2
    assert depths["commons-fileupload:commons-fileupload"] == 1
