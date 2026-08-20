"""Phase JSON schemaVersion helpers."""

from __future__ import annotations

from typing import Any

from lightwell_shared import SCHEMA_VERSION


class SchemaError(ValueError):
    """plan/collect/apply JSON schemaVersion mismatch or missing."""


def stamp(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy with schemaVersion set."""
    out = dict(payload)
    out["schemaVersion"] = SCHEMA_VERSION
    return out


def require_schema(payload: dict[str, Any], *, label: str = "json") -> None:
    """Raise SchemaError unless schemaVersion matches SCHEMA_VERSION."""
    got = payload.get("schemaVersion")
    if got is None:
        raise SchemaError(f"{label}: missing schemaVersion (want {SCHEMA_VERSION})")
    if got != SCHEMA_VERSION:
        raise SchemaError(f"{label}: schemaVersion {got!r} != {SCHEMA_VERSION}")
