#!/usr/bin/env python3
"""Plan phase: inventory direct Maven dependencies from pom.xml (no network)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lightwell-shared" / "scripts"))

from lightwell_shared.directs_plan import main

if __name__ == "__main__":
    raise SystemExit(main())
