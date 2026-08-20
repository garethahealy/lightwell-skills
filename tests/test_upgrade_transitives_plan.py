"""Unit tests for upgrade-transitives plan inventory + tree fingerprint."""

from __future__ import annotations

import tempfile
from pathlib import Path

from _paths import FIXTURES
from lightwell_shared.transitives_plan import (
    build_inventory,
    pom_fingerprint,
    save_tree_with_fingerprint,
    try_reuse_tree,
)


def test_build_inventory() -> None:
    pom = (FIXTURES / "sample_pom.xml").read_text(encoding="utf-8")
    tree = (FIXTURES / "tree.txt").read_text(encoding="utf-8")
    inv = build_inventory(pom, tree)
    cand = {c["ga"]: c for c in inv["candidates"]}
    promoted = {p["ga"] for p in inv["promoted"]}
    assert "commons-io:commons-io" in promoted
    assert "commons-io:commons-io" not in cand
    assert "org.json:json" not in cand
    assert "junit:junit" not in cand
    assert "org.yaml:snakeyaml" in cand
    assert cand["org.yaml:snakeyaml"]["viaParents"] == ["com.fasterxml.jackson.dataformat:jackson-dataformat-yaml"]
    assert cand["org.yaml:snakeyaml"]["treeVersion"] == "2.0"
    assert "org.apache.commons:commons-lang3" in cand


def test_tree_fingerprint_reuse() -> None:
    pom = "pom-a"
    sha = pom_fingerprint(pom)
    with tempfile.TemporaryDirectory() as tmp:
        tree_path = Path(tmp) / "out.tree.txt"
        save_tree_with_fingerprint(tree_path, "TREE", sha)
        reused = try_reuse_tree(tree_path, sha, force=False)
        assert reused == "TREE"
        assert try_reuse_tree(tree_path, sha, force=True) is None
        assert try_reuse_tree(tree_path, "other", force=False) is None
