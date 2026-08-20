"""Plan phase: inventory direct Maven dependencies from pom.xml (no network)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from lightwell_shared.pom_lib import parse_pom
from lightwell_shared.runtime import require_python
from lightwell_shared.schema import stamp


def build_direct_plan(pom_text: str, pom_path: Path) -> dict[str, Any]:
    pom = parse_pom(pom_text)
    return stamp(
        {
            "pom": str(pom_path.resolve()),
            "dependencies": pom["directs"],
            "promotedSkipped": [{"ga": p["ga"], "version": p["version"], "via": p["via"]} for p in pom["promoted"]],
        }
    )


def main() -> int:
    require_python()
    parser = argparse.ArgumentParser(description="Plan phase: inventory direct Maven dependencies from pom.xml.")
    parser.add_argument(
        "pom_positional",
        nargs="?",
        default="",
        help="Path to pom.xml (default: pom.xml)",
    )
    parser.add_argument("--pom", default="", help="Path to pom.xml")
    parser.add_argument(
        "-o",
        "--output",
        default="",
        help="Write JSON to this path (also prints to stdout)",
    )
    args = parser.parse_args()

    pom_path = Path(args.pom or args.pom_positional or "pom.xml")
    if not pom_path.is_file():
        print(f"error: pom not found: {pom_path}", file=sys.stderr)
        return 2

    inventory = build_direct_plan(pom_path.read_text(encoding="utf-8"), pom_path)
    text = json.dumps(inventory, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    return 0
