"""Unit tests for API advisory matching. No HTTP."""

from __future__ import annotations

from pathlib import Path

from lightwell_shared.fetch_osv import fetch_osv_lines_for_bumps, match_lines_for_advisories
from lightwell_shared.lightwell_urls import OSV_REMEDIATED_BASE

_ADVISORY = {
    "advisory_id": "RHSA-TEST-1",
    "aliases": ["CVE-2023-0001"],
    "summary": "Test advisory for json",
    "package_name": "org.json:json",
    "fixed_versions": ["20220320.0.0.rhlw-00003"],
}


def test_match_lines_keep_osv_shape() -> None:
    lines = match_lines_for_advisories(
        [("org.json", "json", "20220320", "20220320.0.0.rhlw-00003")],
        {"org.json:json": [_ADVISORY]},
    )
    assert lines == [
        "org.json:json|CVE-2023-0001|Test advisory for json|fixed=20220320.0.0.rhlw-00003"
        f"|osv={OSV_REMEDIATED_BASE}/RHSA-TEST-1.json"
    ]


def test_match_lines_skip_other_packages_and_already_fixed() -> None:
    other = dict(_ADVISORY, package_name="json")
    purl = dict(_ADVISORY, package_name="pkg:maven/org.json/json@20220320")
    assert (
        match_lines_for_advisories(
            [("org.json", "json", "20220320", "20220320.0.0.rhlw-00003")],
            {"org.json:json": [other]},
        )
        == []
    )
    assert (
        match_lines_for_advisories(
            [("org.json", "json", "20220320.0.0.rhlw-00003", "20220320.0.0.rhlw-00004")],
            {"org.json:json": [_ADVISORY]},
        )
        == []
    )
    lines = match_lines_for_advisories(
        [("org.json", "json", "20220320", "20220320.0.0.rhlw-00003")],
        {"org.json:json": [purl]},
    )
    assert len(lines) == 1
    assert lines[0].endswith(f"|osv={OSV_REMEDIATED_BASE}/RHSA-TEST-1.json")


def test_fetch_uses_cache(tmp_path: Path, monkeypatch) -> None:
    calls = {"n": 0}

    def fake(group_id: str, artifact_id: str) -> list[dict]:
        calls["n"] += 1
        assert (group_id, artifact_id) == ("org.json", "json")
        return [_ADVISORY]

    monkeypatch.setenv("LIGHTWELL_OSV_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("LIGHTWELL_OSV_CACHE_TTL", "3600")
    monkeypatch.setenv("LIGHTWELL_CLIENT_ID", "client-id")
    monkeypatch.setenv("LIGHTWELL_CLIENT_SECRET", "client-secret")
    monkeypatch.delenv("LIGHTWELL_OSV_NO_CACHE", raising=False)
    monkeypatch.setattr("lightwell_shared.fetch_osv.list_advisories", fake)
    bumps = [("org.json", "json", "20220320", "20220320.0.0.rhlw-00003")]
    first = fetch_osv_lines_for_bumps(bumps)
    second = fetch_osv_lines_for_bumps(bumps)
    assert first == second
    assert calls["n"] == 1
    assert "pulp-content/lightwell" in first[0]
