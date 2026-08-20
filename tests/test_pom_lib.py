"""Unit tests for pom_lib tree helpers and SemVer policy."""

from __future__ import annotations

from lightwell_shared.pom_lib import (
    ask_reason,
    indexes_by_via_direct,
    is_newer,
    needs_ask,
    semver_triple,
    versions_by_ga,
)

COMBINED = """\
tmp.lightwell:natural-check:jar:0.0.0
+- parent.one:a:jar:1.0:compile
|  +- dep:x:jar:9.0:compile
|  \\- dep:y:war:8.0:compile
\\- parent.two:b:bundle:2.0:compile
   \\- dep:x:jar:9.1:compile (omitted for duplicate)
"""


def test_indexes_by_via_direct() -> None:
    by_via = indexes_by_via_direct(COMBINED)
    assert "parent.one:a" in by_via
    assert "parent.two:b" in by_via
    assert by_via["parent.one:a"]["dep:x"] == "9.0"
    assert by_via["parent.one:a"]["dep:y"] == "8.0"
    assert by_via["parent.two:b"]["dep:x"] == "9.1"
    assert by_via["parent.one:a"]["parent.one:a"] == "1.0"


def test_versions_by_ga_first_wins() -> None:
    v = versions_by_ga(COMBINED)
    assert v["dep:x"] == "9.0"
    assert v["dep:y"] == "8.0"


def test_semver_triple() -> None:
    assert semver_triple("1.2.3") == (1, 2, 3)
    assert semver_triple("1.2.3.rhlw-00001") == (1, 2, 3)
    assert semver_triple("20220320") == (20220320, 0, 0)
    assert semver_triple("20220320.0.0.rhlw-00003") == (20220320, 0, 0)
    assert semver_triple("${foo}") is None


def test_never_downgrade() -> None:
    assert is_newer("1.2.4", "1.2.3")
    assert not is_newer("1.2.3", "1.2.4")
    assert not is_newer("1.2.3.rhlw-00001", "1.2.4")
    assert is_newer("1.2.3.rhlw-00002", "1.2.3.rhlw-00001")
    assert is_newer("1.2.3.rhlw-00001", "1.2.3")


def test_needs_ask_semver_policy() -> None:
    g = "org.example"
    assert not needs_ask(g, "1.2.3", "1.2.4")
    assert not needs_ask(g, "1.2.3", "1.2.4.rhlw-00001")
    assert not needs_ask(g, "1.2.3", "1.2.3.rhlw-00001")
    assert ask_reason("1.2.3", "1.2.3.rhlw-00001") == "semver-patch-same"
    assert needs_ask(g, "1.2.3", "1.3.0")
    assert ask_reason("1.2.3", "1.3.0") == "semver-minor"
    assert needs_ask(g, "1.2.3", "2.0.0")
    assert ask_reason("1.2.3", "2.0.0") == "semver-major"
    assert needs_ask(g, "weird", "1.0.0")
    assert ask_reason("weird", "1.0.0") == "semver-unsure"
