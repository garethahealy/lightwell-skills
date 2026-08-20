#!/usr/bin/env python3
"""Apply phase: edit pom.xml from direct Collect results, then mvn clean install."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lightwell-shared" / "scripts"))

from lightwell_shared.directs_apply import main

if __name__ == "__main__":
    raise SystemExit(main())
