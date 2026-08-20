"""Summary phase helpers for direct upgrades."""

from __future__ import annotations

from typing import Any

from lightwell_shared.runtime import require_python
from lightwell_shared.summary_common import run_upgrade_summary


def format_row(r: dict[str, Any], was_applied: bool) -> str:
    action = r.get("action", "")
    if was_applied:
        action = f"{action} (applied)"
    return f"| `{r.get('ga')}` | `{r.get('from')}` | `{r.get('to')}` | {r.get('catalog') or ''} | {action} |"


def select_osv(applied_rows: list[dict[str, Any]]) -> list[tuple[str, str, str, str]]:
    bumps: list[tuple[str, str, str, str]] = []
    for r in applied_rows:
        if (r.get("catalog") == "remediated" or ".rhlw-" in str(r.get("to") or "")) and r.get("to"):
            bumps.append((r["groupId"], r["artifactId"], str(r.get("from")), str(r["to"])))
    return bumps


def main() -> int:
    require_python()
    return run_upgrade_summary(
        title="## Upgrade directs summary",
        table_headers=["Artifact", "From", "To", "Catalog", "Action"],
        format_collect_row=format_row,
        select_osv_bumps=select_osv,
        osv_heading="### CVEs (remediated bumps)",
        description="Summary phase: table + OSV for direct upgrades.",
    )
