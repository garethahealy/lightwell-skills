"""Unit tests for the shipped PNC provenance signing key."""

from __future__ import annotations

from lightwell_shared.verify_attestations import AttestRow, format_report, signing_key_path, signing_key_ready


def test_format_report_matches_upgrade_summary_table() -> None:
    rows = [
        AttestRow("OK", "org.json:json:20220320.0.0.rhlw-00003", "remediated", "verified", True),
        AttestRow("FAIL", "commons-io:commons-io:2.11.0.rhlw-00011", "remediated", "HTTP 404", False),
        AttestRow("FAIL", "com.fasterxml.woodstox:woodstox-core:6.0.3.rhlw-00001", "remediated", "jar-missing", False),
    ]
    report = format_report(rows)
    assert report.startswith("\n## Provenance\n\n")
    assert "| Status | Package | Catalog | Detail |\n|------|------|------|------|\n" in report
    assert "| OK | `org.json:json:20220320.0.0.rhlw-00003` | remediated | verified |" in report
    assert "| FAIL | `commons-io:commons-io:2.11.0.rhlw-00011` | remediated | HTTP 404 |" in report
    assert "| FAIL | `com.fasterxml.woodstox:woodstox-core:6.0.3.rhlw-00001` | remediated | jar-missing |" in report


def test_signing_key_is_shipped_pem() -> None:
    path = signing_key_path()
    assert path.name == "pnc-provenance-signing-key-1.pub"
    assert signing_key_ready(path)
