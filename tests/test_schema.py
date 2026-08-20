"""Unit tests for phase JSON schemaVersion helpers."""

from __future__ import annotations

import pytest

from lightwell_shared import SCHEMA_VERSION
from lightwell_shared.schema import SchemaError, require_schema, stamp


def test_stamp_sets_schema_version() -> None:
    out = stamp({"pom": "x"})
    assert out["schemaVersion"] == SCHEMA_VERSION
    require_schema(out, label="ok")


def test_require_schema_missing() -> None:
    with pytest.raises(SchemaError, match="missing schemaVersion"):
        require_schema({}, label="missing")


def test_require_schema_mismatch() -> None:
    with pytest.raises(SchemaError, match="schemaVersion"):
        require_schema({"schemaVersion": SCHEMA_VERSION + 1}, label="bad")
