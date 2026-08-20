"""Unit tests for parse-renovate-bumps.parse_body."""

from __future__ import annotations

from _paths import FIXTURES
from lightwell_shared.parse_renovate_bumps import parse_body


def test_parse_body_maven_rows_only() -> None:
    text = (FIXTURES / "renovate_pr.md").read_text(encoding="utf-8")
    bumps = parse_body(text)
    assert ("org.json", "json", "20220320", "20220320.0.0.rhlw-00003") in bumps
    assert ("commons-io", "commons-io", "2.11.0", "2.11.0.rhlw-00001") in bumps
    assert ("com.fasterxml.jackson.core", "jackson-core", "2.17.0", "2.17.1") in bumps
    packages = {f"{g}:{a}" for g, a, _f, _t in bumps}
    assert "actions/checkout" not in packages
    assert sum(1 for b in bumps if b[0] == "org.json") == 1


def test_rhlw_only_filter() -> None:
    text = (FIXTURES / "renovate_pr.md").read_text(encoding="utf-8")
    bumps = [b for b in parse_body(text) if ".rhlw-" in b[2] or ".rhlw-" in b[3]]
    assert all(".rhlw-" in b[2] or ".rhlw-" in b[3] for b in bumps)
    assert ("com.fasterxml.jackson.core", "jackson-core", "2.17.0", "2.17.1") not in bumps


def test_same_from_to_skipped() -> None:
    body = """
| Package | Change |
| --- | --- |
| [org.json:json](https://example.invalid) | `1.0.0` → `1.0.0` |
"""
    assert parse_body(body) == []
