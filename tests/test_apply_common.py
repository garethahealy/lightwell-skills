"""Unit tests for apply_common.apply_rows."""

from __future__ import annotations

from lightwell_shared.apply_common import apply_rows
from lightwell_shared.summary_common import effective_action


def test_prepare_row_records_effective_action() -> None:
    rows = [
        {
            "action": "ASK",
            "pending": "PROMOTE",
            "ga": "g:a",
            "groupId": "g",
            "artifactId": "a",
            "from": "1.0.0",
            "to": "1.0.0.rhlw-00001",
        }
    ]

    def prepare(row: dict) -> dict:
        out = dict(row)
        out["action"] = row["pending"]
        out["collectAction"] = "ASK"
        return out

    text, applied, skipped = apply_rows(
        "<pom/>",
        rows,
        should_apply=lambda r: r.get("action") == "ASK",
        mutator=lambda t, _r: t,
        prepare_row=prepare,
        dry_run=False,
    )
    assert text == "<pom/>"
    assert not skipped
    assert len(applied) == 1
    assert applied[0]["action"] == "PROMOTE"
    assert applied[0]["appliedAction"] == "PROMOTE"
    assert applied[0]["collectAction"] == "ASK"
    assert effective_action(applied[0]) == "PROMOTE"


def test_apply_rows_records_mutator_error() -> None:
    def boom(_text: str, _row: dict) -> str:
        raise ValueError("no-parent")

    text, applied, skipped = apply_rows(
        "<pom/>",
        [{"action": "UPGRADE", "ga": "g:a"}],
        should_apply=lambda r: r["action"] == "UPGRADE",
        mutator=boom,
        dry_run=False,
    )
    assert text == "<pom/>"
    assert not applied
    assert skipped[0]["skipReason"] == "no-parent"


def test_apply_rows_dry_run_skips_mutator() -> None:
    def boom(_text: str, _row: dict) -> str:
        raise ValueError("no-parent")

    text, applied, skipped = apply_rows(
        "<pom/>",
        [{"action": "UPGRADE", "ga": "g:a"}],
        should_apply=lambda r: r["action"] == "UPGRADE",
        mutator=boom,
        dry_run=True,
    )
    assert text == "<pom/>"
    assert applied[0]["dryRun"] is True
    assert not skipped
