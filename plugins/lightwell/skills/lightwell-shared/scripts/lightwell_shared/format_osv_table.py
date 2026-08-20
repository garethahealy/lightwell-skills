"""Format fetch_osv.py lines into a PR comment or table.

CLI entry for ``scripts/format-osv-table.py``. Stdin is OSV pipe lines.
"""

from __future__ import annotations

import argparse
import sys

from lightwell_shared.runtime import require_python
from lightwell_shared.summary_common import format_osv_comment_body, format_osv_table


def main() -> int:
    require_python()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--comment",
        action="store_true",
        help="Emit full PR comment body (marker + heading + table + footer)",
    )
    parser.add_argument(
        "--marker",
        default="<!-- lightwell-osv-summary -->",
        help="HTML comment marker for --comment mode",
    )
    parser.add_argument(
        "--heading",
        default="### CVEs (remediated)",
        help="Section heading when not using --comment",
    )
    args = parser.parse_args()
    lines = [ln.strip() for ln in sys.stdin if ln.strip()]
    if args.comment:
        sys.stdout.write(format_osv_comment_body(lines, marker=args.marker))
    else:
        sys.stdout.write("\n".join(format_osv_table(lines, heading=args.heading)) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
