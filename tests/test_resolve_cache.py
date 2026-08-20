"""Unit tests for resolve_metadata disk cache / TTL (no network)."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

import pytest

from lightwell_shared.resolve_metadata import (
    MetadataError,
    _memo,
    cache_fresh,
    coord_cache_dir,
    resolve_payload,
    write_text_atomic,
)


@pytest.fixture(autouse=True)
def _clear_memo() -> None:
    _memo.clear()
    yield
    _memo.clear()


def test_cache_fresh_respects_ttl(tmp_path: Path) -> None:
    cdir = tmp_path / "c"
    cdir.mkdir()
    write_text_atomic(cdir / "fetched_at", str(int(time.time())))
    assert cache_fresh(cdir, ttl=3600)
    write_text_atomic(cdir / "fetched_at", str(int(time.time()) - 4000))
    assert not cache_fresh(cdir, ttl=3600)


def test_resolve_payload_uses_cached_latest(tmp_path: Path) -> None:
    cdir = coord_cache_dir(tmp_path, "remediated", "org.json", "json")
    cdir.mkdir(parents=True)
    write_text_atomic(cdir / "fetched_at", str(int(time.time())))
    write_text_atomic(cdir / "latest", "20220320.0.0.rhlw-00003")
    write_text_atomic(
        cdir / "maven-metadata.xml",
        "<metadata><latest>20220320.0.0.rhlw-00003</latest></metadata>",
    )
    with patch(
        "lightwell_shared.resolve_metadata.fetch_metadata_http",
        side_effect=AssertionError("should not fetch"),
    ):
        ver = resolve_payload(
            "remediated",
            "org.json",
            "json",
            tag="latest",
            same_base_current=None,
            cache_root=tmp_path,
            ttl=3600,
            username="u",
            token="t",
        )
    assert ver == "20220320.0.0.rhlw-00003"


def test_resolve_payload_expired_ttl_refetches(tmp_path: Path) -> None:
    cdir = coord_cache_dir(tmp_path, "remediated", "org.json", "json")
    cdir.mkdir(parents=True)
    write_text_atomic(cdir / "fetched_at", str(int(time.time()) - 9999))
    write_text_atomic(cdir / "latest", "stale")
    xml = """<metadata><latest>fresh.rhlw-00001</latest>
      <versions><version>fresh.rhlw-00001</version></versions></metadata>"""
    with patch(
        "lightwell_shared.resolve_metadata.fetch_metadata_http",
        return_value=(200, xml, {}),
    ) as fetch:
        ver = resolve_payload(
            "remediated",
            "org.json",
            "json",
            tag="latest",
            same_base_current=None,
            cache_root=tmp_path,
            ttl=60,
            username="u",
            token="t",
        )
    assert ver == "fresh.rhlw-00001"
    fetch.assert_called_once()


def test_same_base_sidecar_hit(tmp_path: Path) -> None:
    from lightwell_shared.resolve_metadata import same_base_sidecar_name

    cdir = coord_cache_dir(tmp_path, "remediated", "org.json", "json")
    cdir.mkdir(parents=True)
    write_text_atomic(cdir / "fetched_at", str(int(time.time())))
    write_text_atomic(
        cdir / same_base_sidecar_name("20220320"),
        "20220320.0.0.rhlw-00003",
    )
    with patch(
        "lightwell_shared.resolve_metadata.fetch_metadata_http",
        side_effect=AssertionError("should not fetch"),
    ):
        ver = resolve_payload(
            "remediated",
            "org.json",
            "json",
            tag=None,
            same_base_current="20220320",
            cache_root=tmp_path,
            ttl=3600,
            username="u",
            token="t",
        )
    assert ver == "20220320.0.0.rhlw-00003"


def test_negative_cache_raises(tmp_path: Path) -> None:
    cdir = coord_cache_dir(tmp_path, "remediated", "org.json", "json")
    cdir.mkdir(parents=True)
    write_text_atomic(cdir / "fetched_at", str(int(time.time())))
    write_text_atomic(cdir / "negative", "METADATA_FETCH_FAILED: HTTP 404")
    with pytest.raises(MetadataError, match="METADATA_FETCH_FAILED"):
        resolve_payload(
            "remediated",
            "org.json",
            "json",
            tag="latest",
            same_base_current=None,
            cache_root=tmp_path,
            ttl=3600,
            username="u",
            token="t",
        )
