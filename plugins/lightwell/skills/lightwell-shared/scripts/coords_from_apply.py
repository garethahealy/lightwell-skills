#!/usr/bin/env python3
"""CLI shim: apply JSON → attest coordinate lines."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lightwell_shared.coords_from_apply import main

if __name__ == "__main__":
    raise SystemExit(main())
