"""Unit tests for match_osv_cves (fixture advisories, no HTTP)."""

from __future__ import annotations

from _paths import FIXTURES
from lightwell_shared.match_osv_cves import (
    advisory_labels,
    advisory_summary,
    fixed_in_ranges,
    load_advisories_for_bumps,
    match_bumps,
    package_names_for_affected,
    parse_advisory,
)


def test_package_names_from_name_and_purl() -> None:
    names = package_names_for_affected(
        {
            "package": {
                "name": "org.json:json",
                "purl": "pkg:maven/org.json/json@20220320",
            }
        }
    )
    assert "org.json:json" in names


def test_fixed_in_ranges() -> None:
    fixes = fixed_in_ranges({"ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.3.rhlw-00001"}]}]})
    assert fixes == {"1.2.3.rhlw-00001"}


def test_advisory_labels_prefer_cve() -> None:
    assert advisory_labels({"id": "RHSA-1", "aliases": ["CVE-2023-0001"]}) == ["CVE-2023-0001"]
    assert advisory_labels({"id": "RHSA-1", "aliases": []}) == ["RHSA-1"]


def test_advisory_summary_truncates() -> None:
    long = "x" * 250
    out = advisory_summary({"summary": long}, limit=20)
    assert out.endswith("...")
    assert len(out) == 20


def test_match_bumps_fixed_in_to_not_from() -> None:
    parsed = parse_advisory(FIXTURES / "osv" / "RHSA-TEST-1.json")
    assert parsed is not None
    entries, labels, summary, _names, url = parsed
    advisories = [(entries, labels, summary, url)]
    hits = match_bumps(
        [("org.json:json", "20220320", "20220320.0.0.rhlw-00003")],
        advisories,
    )
    assert len(hits) == 1
    assert hits[0].startswith("org.json:json|CVE-2023-0001|")
    assert "fixed=20220320.0.0.rhlw-00003" in hits[0]
    assert "osv=" in hits[0]

    already_fixed = match_bumps(
        [("org.json:json", "20220320.0.0.rhlw-00003", "20220320.0.0.rhlw-00004")],
        advisories,
    )
    assert already_fixed == []

    wrong_pkg = match_bumps(
        [("commons-io:commons-io", "2.11.0", "20220320.0.0.rhlw-00003")],
        advisories,
    )
    assert wrong_pkg == []


def test_load_advisories_for_bumps_from_dir() -> None:
    root = FIXTURES / "osv"
    bumps = [("org.json:json", "20220320", "20220320.0.0.rhlw-00003")]
    advisories, errors = load_advisories_for_bumps(root, bumps, index=None)
    assert errors == 0
    assert match_bumps(bumps, advisories)
