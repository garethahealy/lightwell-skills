#!/usr/bin/env python3
"""CLI shim: verify Lightwell jar attestations with cosign."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lightwell_shared.verify_attestations import main

if __name__ == "__main__":
    raise SystemExit(main())
