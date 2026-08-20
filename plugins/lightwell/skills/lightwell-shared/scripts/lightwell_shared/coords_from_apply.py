"""Emit verify-attestations stdin lines from an apply-phase JSON.

Usage:
  coords_from_apply.py --from-apply apply.json
  coords_from_apply.py --from-apply apply.json | \\
    bash ../lightwell-shared/scripts/verify-attestations.sh --batch

Prints one line per applied Lightwell bump:
  catalog groupId artifactId version

Requires Python 3.14+.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from lightwell_shared.runtime import require_python


def rows_to_coords(apply: dict) -> list[tuple[str, str, str, str]]:
    out: list[tuple[str, str, str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for r in apply.get("applied") or []:
        g = r.get("groupId")
        a = r.get("artifactId")
        ver = r.get("to") or r.get("from")
        if not g or not a or not ver:
            continue
        action = r.get("action") or r.get("appliedAction") or ""
        if action == "DROP":
            continue
        catalog = r.get("catalog") or "remediated"
        if catalog not in {"remediated", "validated"}:
            # Transitive promotes are always remediated
            if ".rhlw-" in str(ver):
                catalog = "remediated"
            else:
                continue
        row = (catalog, str(g), str(a), str(ver))
        if row in seen:
            continue
        seen.add(row)
        out.append(row)
    return out


def main() -> int:
    require_python()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from-apply", required=True)
    args = parser.parse_args()
    apply = json.loads(Path(args.from_apply).read_text(encoding="utf-8"))
    for catalog, g, a, ver in rows_to_coords(apply):
        print(f"{catalog} {g} {a} {ver}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
