"""Shared summary / OSV markdown helpers for upgrade skills and add-osv."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from lightwell_shared.download_http import HttpAuthError
from lightwell_shared.fetch_osv import fetch_osv_lines_for_bumps
from lightwell_shared.lightwell_urls import OSV_REMEDIATED_BASE
from lightwell_shared.schema import require_schema


class OsvAuthError(RuntimeError):
    """packages.redhat.com rejected OSV credentials (HTTP 401/403)."""


class OsvFetchError(RuntimeError):
    """OSV helper failed for a non-auth reason."""


def fetch_osv_lines(bumps: list[tuple[str, str, str, str]]) -> list[str]:
    """Return raw pipe-delimited OSV match lines (in-process, no subprocess).

    Raises OsvAuthError on AUTH_FAILED / HTTP 401/403 (caller must stop).
    Raises OsvFetchError on other failures.
    """
    if not bumps:
        return []
    try:
        return fetch_osv_lines_for_bumps(bumps)
    except HttpAuthError as exc:
        print(str(exc), file=sys.stderr)
        raise OsvAuthError(str(exc)) from exc
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        raise OsvFetchError(str(exc)) from exc


def osv_line_to_markdown_row(raw: str) -> str | None:
    """Convert one fetch_osv stdout line to a markdown table row."""
    parts = raw.split("|")
    if len(parts) < 5:
        return None
    pkg, cve, summary, fixed, osv = parts[0], parts[1], parts[2], parts[3], parts[4]
    fixed_ver = fixed.removeprefix("fixed=")
    osv_url = osv.removeprefix("osv=")
    summary = summary.replace("|", "\\|")
    cve_cell = f"[`{cve}`]({osv_url})" if osv_url else f"`{cve}`"
    return f"| `{pkg}` | {cve_cell} | {summary} | `{fixed_ver}` |"


def format_osv_table(
    osv_lines: list[str],
    *,
    heading: str = "### CVEs (remediated)",
) -> list[str]:
    """Markdown section for OSV matches."""
    rows = [row for ln in osv_lines if (row := osv_line_to_markdown_row(ln))]
    if not rows:
        return []
    return [
        "",
        heading,
        "",
        "| Package | CVE / advisory | Summary | Fixed in |",
        "|---------|----------------|---------|----------|",
        *rows,
    ]


def format_osv_comment_body(osv_lines: list[str], *, marker: str) -> str:
    """Full PR comment body used by add-osv-to-renovate."""
    lines = [
        marker,
        "## Lightwell OSV advisories fixed by this update",
        "",
        "| Package | CVE / advisory | Summary | Fixed in |",
        "|---------|----------------|---------|----------|",
    ]
    for raw in osv_lines:
        row = osv_line_to_markdown_row(raw)
        if row:
            lines.append(row)
    lines.extend(
        [
            "",
            f"_Source: Lightwell remediated OSV (`{OSV_REMEDIATED_BASE}`)._",
            "",
        ]
    )
    return "\n".join(lines)


def build_footer(build: dict | None) -> list[str]:
    if not build:
        return []
    lines = [
        "",
        f"Build: {'ok' if build.get('ok') else 'FAILED'} (exit {build.get('exitCode')})",
    ]
    for dl in build.get("lightwellDownloads") or []:
        lines.append(f"- `{dl}`")
    return lines


def write_markdown(lines: list[str], output: str) -> None:
    text = "\n".join(lines) + "\n"
    if output:
        Path(output).write_text(text, encoding="utf-8")
    sys.stdout.write(text)


def effective_action(row: dict[str, Any]) -> str:
    """Action recorded on apply JSON (prefers appliedAction after ASK remap)."""
    return str(row.get("appliedAction") or row.get("action") or "")


def run_upgrade_summary(
    *,
    title: str,
    table_headers: list[str],
    format_collect_row: Callable[[dict[str, Any], bool], str],
    select_osv_bumps: Callable[[list[dict[str, Any]]], list[tuple[str, str, str, str]]],
    osv_heading: str,
    description: str,
) -> int:
    """CLI entry for upgrade-directs / upgrade-transitives summary.py."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--from-collect", required=True)
    parser.add_argument(
        "--from-apply",
        required=True,
        help="Apply JSON (required so OSV only covers applied bumps)",
    )
    parser.add_argument("--skip-osv", action="store_true")
    parser.add_argument("-o", "--output", default="")
    args = parser.parse_args()

    collect = json.loads(Path(args.from_collect).read_text(encoding="utf-8"))
    apply = json.loads(Path(args.from_apply).read_text(encoding="utf-8"))
    try:
        require_schema(collect, label=args.from_collect)
        require_schema(apply, label=args.from_apply)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    applied_rows = list(apply.get("applied") or [])
    applied_gas = {r.get("ga") for r in applied_rows}
    header_line = "| " + " | ".join(table_headers) + " |"
    sep_line = "|" + "|".join("------" for _ in table_headers) + "|"
    lines = [title, "", header_line, sep_line]
    for r in collect.get("results") or []:
        was_applied = bool(applied_gas and r.get("ga") in applied_gas)
        lines.append(format_collect_row(r, was_applied))

    if not args.skip_osv:
        osv_bumps = select_osv_bumps(applied_rows)
        if osv_bumps:
            try:
                osv_lines = fetch_osv_lines(osv_bumps)
            except OsvAuthError as exc:
                print(
                    f"AUTH_FAILED: validate LIGHTWELL_TOKEN ({exc})",
                    file=sys.stderr,
                )
                return 1
            except OsvFetchError:
                return 1
            lines.extend(format_osv_table(osv_lines, heading=osv_heading))

    lines.extend(build_footer(apply.get("build")))
    write_markdown(lines, args.output)
    return 0
