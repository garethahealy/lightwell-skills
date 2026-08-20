"""Unit tests for fetch_osv.manifest parsing (no HTTP)."""

from __future__ import annotations

from lightwell_shared.fetch_osv import parse_manifest


def test_parse_manifest() -> None:
    raw = "\n".join(
        [
            "RHSA-1.json,abc123,1",
            "bad name.json,x,1",
            "ok-2.json,def456,99",
            "",
        ]
    )
    entries = parse_manifest(raw)
    assert entries == [("RHSA-1.json", "abc123"), ("ok-2.json", "def456")]
