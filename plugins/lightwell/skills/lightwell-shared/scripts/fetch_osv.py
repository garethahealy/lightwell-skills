#!/usr/bin/env python3
"""CLI shim: fetch Lightwell remediated OSV matches."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lightwell_shared.fetch_osv import main

if __name__ == "__main__":
    raise SystemExit(main())
