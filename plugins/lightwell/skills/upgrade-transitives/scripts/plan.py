#!/usr/bin/env python3
"""Plan phase: transitive inventory from dependency:tree + pom."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lightwell-shared" / "scripts"))

from lightwell_shared.transitives_plan import main

if __name__ == "__main__":
    raise SystemExit(main())
