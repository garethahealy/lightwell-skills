"""Summary phase helpers for transitive upgrades."""

from __future__ import annotations

from typing import Any

from lightwell_shared.runtime import require_python
from lightwell_shared.summary_common import effective_action, run_upgrade_summary


def format_row(r: dict[str, Any], was_applied: bool) -> str:
    action = r.get("action", "")
    if was_applied:
        action = f"{action} (applied)"
    via = ",".join(r.get("via") or []) or "-"
    return f"| `{r.get('ga')}` | `{r.get('from')}` | `{r.get('to')}` | `{via}` | {action} |"


def select_osv(applied_rows: list[dict[str, Any]]) -> list[tuple[str, str, str, str]]:
    bumps: list[tuple[str, str, str, str]] = []
    for r in applied_rows:
        action = effective_action(r)
        if action in {"PROMOTE", "UPDATE"} and r.get("to") and r.get("from"):
            bumps.append((r["groupId"], r["artifactId"], str(r["from"]), str(r["to"])))
    return bumps


def main() -> int:
    require_python()
    return run_upgrade_summary(
        title="## Upgrade transitives summary",
        table_headers=["Artifact", "From", "To", "Via", "Action"],
        format_collect_row=format_row,
        select_osv_bumps=select_osv,
        osv_heading="### CVEs (remediated promote/update)",
        description="Summary phase: table + OSV for transitive upgrades.",
    )
