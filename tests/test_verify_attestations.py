"""Unit tests for the shipped PNC provenance signing key."""

from __future__ import annotations

from lightwell_shared.verify_attestations import signing_key_path, signing_key_ready


def test_signing_key_is_shipped_pem() -> None:
    path = signing_key_path()
    assert path.name == "pnc-provenance-signing-key-1.pub"
    assert signing_key_ready(path)
