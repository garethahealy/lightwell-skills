#!/usr/bin/env python3
"""Summary phase: markdown table + OSV for applied remediated direct bumps."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lightwell-shared" / "scripts"))

from lightwell_shared.directs_summary import main

if __name__ == "__main__":
    raise SystemExit(main())
