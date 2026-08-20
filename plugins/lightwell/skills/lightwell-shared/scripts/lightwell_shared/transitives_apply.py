"""Apply phase helpers for transitive promote/update/drop."""

from __future__ import annotations

from lightwell_shared.apply_common import run_apply
from lightwell_shared.pom_edit import apply_transitive_collect_row


def prepare_ask_row(row: dict) -> dict:
    """Map ASK → pending PROMOTE/UPDATE when user approved via --include-ask."""
    if row.get("action") != "ASK":
        return row
    pending = row.get("pending")
    if pending not in {"PROMOTE", "UPDATE"}:
        raise ValueError(f"ASK row missing pending PROMOTE/UPDATE: {row.get('ga')}")
    out = dict(row)
    out["action"] = pending
    out["collectAction"] = "ASK"
    return out


def should_apply(row: dict, include_ask: bool) -> bool:
    action = row.get("action")
    allowed = {"PROMOTE", "UPDATE", "KEEP", "DROP"}
    return action in allowed or (action == "ASK" and include_ask)


def main() -> int:
    return run_apply(
        description="Apply phase: promote/update/drop transitives from Collect JSON.",
        noun="action",
        mutator=apply_transitive_collect_row,
        should_apply=should_apply,
        prepare_ask_row=prepare_ask_row,
        settings_from_collect=True,
        repo_root_from_collect=True,
    )
