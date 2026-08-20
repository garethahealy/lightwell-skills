"""Apply phase helpers for direct dependency bumps."""

from __future__ import annotations

from lightwell_shared.apply_common import run_apply
from lightwell_shared.pom_edit import apply_direct_collect_row


def prepare_ask_row(row: dict) -> dict:
    """Map ASK → UPGRADE when user approved via --include-ask."""
    if row.get("action") != "ASK":
        return row
    out = dict(row)
    out["action"] = "UPGRADE"
    out["collectAction"] = "ASK"
    return out


def should_apply(row: dict, include_ask: bool) -> bool:
    action = row.get("action")
    return action == "UPGRADE" or (action == "ASK" and include_ask)


def mutator(text: str, row: dict) -> str:
    if not row.get("to"):
        raise ValueError("no-target")
    return apply_direct_collect_row(text, row)


def main() -> int:
    return run_apply(
        description="Apply phase: bump direct deps from Collect JSON.",
        noun="bump",
        mutator=mutator,
        should_apply=should_apply,
        prepare_ask_row=prepare_ask_row,
    )
