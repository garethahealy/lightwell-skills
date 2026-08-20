"""Unit tests for summary markdown + select_osv helpers."""

from __future__ import annotations

from lightwell_shared.directs_summary import select_osv as select_osv_directs
from lightwell_shared.summary_common import (
    build_footer,
    format_osv_comment_body,
    format_osv_table,
    osv_line_to_markdown_row,
)
from lightwell_shared.transitives_summary import select_osv as select_osv_transitives

OSV_LINE = (
    "org.json:json|CVE-2023-0001|boom pipe|fixed=20220320.0.0.rhlw-00003|"
    "osv=https://packages.redhat.com/api/pulp-content/public-lightwell-demo/"
    "osv/java/remediated/RHSA-TEST-1.json"
)


def test_osv_line_to_markdown_row() -> None:
    row = osv_line_to_markdown_row(OSV_LINE)
    assert row is not None
    assert "[`CVE-2023-0001`](" in row
    assert "boom pipe" in row
    assert "`20220320.0.0.rhlw-00003`" in row
    assert osv_line_to_markdown_row("too|few") is None


def test_format_osv_table_and_comment() -> None:
    table = format_osv_table([OSV_LINE], heading="### CVEs")
    assert table[1] == "### CVEs"
    assert any("CVE-2023-0001" in ln for ln in table)
    assert format_osv_table(["bad"]) == []
    body = format_osv_comment_body([OSV_LINE], marker="<!-- lightwell-osv-summary -->")
    assert body.startswith("<!-- lightwell-osv-summary -->")
    assert "Lightwell OSV advisories" in body
    assert "public-lightwell-demo/osv/java/remediated" in body


def test_build_footer() -> None:
    assert build_footer(None) == []
    lines = build_footer(
        {
            "ok": True,
            "exitCode": 0,
            "lightwellDownloads": ["Downloaded from lightwell-remediated: org.json"],
        }
    )
    assert "Build: ok (exit 0)" in lines[1]
    assert any("lightwell-remediated" in ln for ln in lines)


def test_select_osv_directs() -> None:
    rows = [
        {
            "groupId": "org.json",
            "artifactId": "json",
            "from": "20220320",
            "to": "20220320.0.0.rhlw-00003",
            "catalog": "remediated",
        },
        {
            "groupId": "g",
            "artifactId": "a",
            "from": "1",
            "to": "2",
            "catalog": "validated",
        },
        {
            "groupId": "x",
            "artifactId": "y",
            "from": "1",
            "to": None,
            "catalog": "remediated",
        },
    ]
    bumps = select_osv_directs(rows)
    assert ("org.json", "json", "20220320", "20220320.0.0.rhlw-00003") in bumps
    assert all(b[1] != "a" for b in bumps)


def test_select_osv_transitives() -> None:
    rows = [
        {
            "groupId": "commons-io",
            "artifactId": "commons-io",
            "from": "2.11.0",
            "to": "2.11.0.rhlw-00001",
            "appliedAction": "PROMOTE",
        },
        {
            "groupId": "g",
            "artifactId": "a",
            "from": "1",
            "to": "2",
            "action": "DROP",
        },
        {
            "groupId": "g",
            "artifactId": "b",
            "from": "1.0.0",
            "to": "1.0.1.rhlw-00001",
            "action": "UPDATE",
        },
    ]
    bumps = select_osv_transitives(rows)
    gas = {(g, a) for g, a, _f, _t in bumps}
    assert ("commons-io", "commons-io") in gas
    assert ("g", "b") in gas
    assert ("g", "a") not in gas
