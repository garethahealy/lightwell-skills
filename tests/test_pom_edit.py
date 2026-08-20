"""Unit tests for pom_edit helpers (sample pom.xml style)."""

from __future__ import annotations

import re

import pytest

from lightwell_shared.pom_edit import (
    bump_direct_dependency,
    ensure_exclusion_on_parent,
    pretty_print_pom,
    remove_exclusion_from_parent,
    remove_promoted_dependency,
    upsert_promoted_dependency,
)

SAMPLE = """\
<?xml version="1.0"?>
<project>
    <dependencies>
        <!-- Source: https://packages.redhat.com/api/pulp-content/public-lightwell-demo/java/remediated/ -->
        <dependency>
            <groupId>org.json</groupId>
            <artifactId>json</artifactId>
            <version>20220320.0.0.rhlw-00001</version>
        </dependency>
        <dependency>
            <groupId>commons-fileupload</groupId>
            <artifactId>commons-fileupload</artifactId>
            <version>1.5</version>
            <exclusions>
                <exclusion>
                    <groupId>commons-io</groupId>
                    <artifactId>commons-io</artifactId>
                </exclusion>
            </exclusions>
        </dependency>
        <!-- Transitive of commons-fileupload:commons-fileupload -->
        <!-- Source: https://packages.redhat.com/api/pulp-content/public-lightwell-demo/java/remediated/ -->
        <dependency>
            <groupId>commons-io</groupId>
            <artifactId>commons-io</artifactId>
            <version>2.11.0.rhlw-00001</version>
        </dependency>
    </dependencies>
</project>
"""


def test_bump_direct_dependency() -> None:
    bumped = bump_direct_dependency(SAMPLE, "org.json", "json", "20220320.0.0.rhlw-00099", catalog="remediated")
    assert "rhlw-00099" in bumped
    assert "org.json" in bumped


def test_upsert_and_remove_promoted_dependency() -> None:
    bumped = bump_direct_dependency(SAMPLE, "org.json", "json", "20220320.0.0.rhlw-00099", catalog="remediated")
    updated = upsert_promoted_dependency(
        bumped,
        "commons-io",
        "commons-io",
        "2.11.0.rhlw-00002",
        ["commons-fileupload:commons-fileupload"],
    )
    assert "rhlw-00002" in updated
    assert "Transitive of commons-fileupload:commons-fileupload" in updated

    dropped = remove_promoted_dependency(updated, "commons-io", "commons-io")
    assert "<!-- Transitive of commons-fileupload" not in dropped
    assert "Transitive of" not in dropped


def test_remove_and_ensure_exclusion() -> None:
    no_excl = remove_exclusion_from_parent(SAMPLE, "commons-fileupload:commons-fileupload", "commons-io", "commons-io")
    assert "commons-io" not in no_excl or "<exclusion>" not in no_excl

    with_excl = ensure_exclusion_on_parent(no_excl, "commons-fileupload:commons-fileupload", "commons-io", "commons-io")
    assert "<exclusion>" in with_excl
    assert "commons-io" in with_excl


def test_ensure_exclusion_missing_parent() -> None:
    with pytest.raises(ValueError, match="parent dependency not found"):
        ensure_exclusion_on_parent(SAMPLE, "missing:parent", "commons-io", "commons-io")


def test_mutations_keep_dependency_indent() -> None:
    bumped = bump_direct_dependency(SAMPLE, "org.json", "json", "20220320.0.0.rhlw-00099", catalog="remediated")
    with_excl = ensure_exclusion_on_parent(SAMPLE, "commons-fileupload:commons-fileupload", "commons-io", "commons-io")
    assert re.search(r"(?m)^[ \t]+<dependency>", bumped)
    assert not re.search(r"(?m)^<dependency>", bumped)
    assert re.search(r"(?m)^[ \t]+</dependency>", with_excl)
    assert not re.search(r"(?m)^</dependency>", with_excl)


def test_pretty_print_pom_idempotent() -> None:
    messy = """\
<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <!-- Source: https://example.invalid/remediated/ -->
<dependency>
            <groupId>org.json</groupId>
            <artifactId>json</artifactId>
            <version>1</version>
        </dependency>
</dependencies>
</project>
"""
    pretty = pretty_print_pom(messy)
    assert pretty == pretty_print_pom(pretty)
    assert "    <dependencies>\n" in pretty
    assert "        <dependency>\n" in pretty
    assert "            <groupId>org.json</groupId>\n" in pretty
    assert "        </dependency>\n" in pretty
    assert "    </dependencies>\n" in pretty
    assert not re.search(r"(?m)^<dependency>", pretty)
    assert not re.search(r"(?m)^</dependencies>", pretty)
