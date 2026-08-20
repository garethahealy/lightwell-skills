"""Emit verify-attestations stdin lines from Lightwell deps in pom.xml."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from lightwell_shared.pom_lib import parse_pom
from lightwell_shared.runtime import require_python


def coords_from_pom(pom_text: str) -> list[tuple[str, str, str, str]]:
    pom = parse_pom(pom_text)
    out: list[tuple[str, str, str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for d in pom["directs"] + pom["promoted"]:
        catalog = d.get("catalog") or ""
        version = str(d.get("version") or "")
        source = d.get("source")
        g = d.get("groupId")
        a = d.get("artifactId")
        if not g or not a or not version:
            continue
        if catalog == "remediated" and ".rhlw-" in version:
            row = (catalog, str(g), str(a), version)
        elif catalog == "validated" and source:
            row = (catalog, str(g), str(a), version)
        else:
            continue
        if row in seen:
            continue
        seen.add(row)
        out.append(row)
    return out


def main() -> int:
    require_python()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pom", default="pom.xml")
    args = parser.parse_args()
    pom_path = Path(args.pom)
    if not pom_path.is_file():
        print(f"error: pom not found: {pom_path}", file=sys.stderr)
        return 2
    for catalog, g, a, ver in coords_from_pom(pom_path.read_text(encoding="utf-8")):
        print(f"{catalog} {g} {a} {ver}")
    return 0
