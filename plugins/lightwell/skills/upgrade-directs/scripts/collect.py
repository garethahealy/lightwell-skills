#!/usr/bin/env python3
"""Collect phase: Lightwell upgrade candidates for directs (batched, cached)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lightwell-shared" / "scripts"))

from lightwell_shared.directs_collect import main

if __name__ == "__main__":
    raise SystemExit(main())
