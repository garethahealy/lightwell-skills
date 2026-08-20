#!/usr/bin/env python3
"""Parse Maven dependency bumps from a Renovate PR body."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lightwell-shared" / "scripts"))

from lightwell_shared.parse_renovate_bumps import main

if __name__ == "__main__":
    raise SystemExit(main())
