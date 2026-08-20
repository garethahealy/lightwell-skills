"""Unit tests for upgrade-directs collect_one."""

from __future__ import annotations

from typing import Any

from lightwell_shared.directs_collect import collect_one


def _dep(**kwargs: Any) -> dict:
    base = {
        "groupId": "org.example",
        "artifactId": "demo",
        "version": "1.0.0",
        "catalog": "remediated",
        "property": None,
    }
    base.update(kwargs)
    return base


def _run(dep: dict, resolve, *, take_latest: bool = False) -> dict:
    return collect_one(
        dep,
        take_latest=take_latest,
        cache_root=None,
        ttl=0,
        username="u",
        token="t",
        resolve=resolve,
    )


def test_remediated_same_base_auto_upgrades() -> None:
    def resolve(catalog, g, a, *, tag, same_base_current, **_kw):
        if catalog == "remediated" and same_base_current == "1.2.3":
            return "1.2.3.rhlw-00002"
        raise AssertionError(f"unexpected resolve: {catalog=} {tag=} {same_base_current=}")

    row = _run(_dep(catalog="remediated", version="1.2.3"), resolve)
    assert row["action"] == "UPGRADE"
    assert row["to"] == "1.2.3.rhlw-00002"
    assert row["catalog"] == "remediated"


def test_remediated_same_base_miss_suggests_remediated_latest() -> None:
    calls: list[tuple] = []

    def resolve(catalog, g, a, *, tag, same_base_current, **_kw):
        calls.append((catalog, tag, same_base_current))
        if catalog == "remediated" and same_base_current == "1.0.0":
            return None
        if catalog == "remediated" and tag == "latest":
            return "2.0.0.rhlw-00001"
        raise AssertionError(f"unexpected resolve: {catalog=} {tag=} {same_base_current=}")

    row = _run(_dep(catalog="remediated", version="1.0.0"), resolve, take_latest=True)
    assert row["action"] == "ASK"
    assert row["to"] == "2.0.0.rhlw-00001"
    assert row["catalog"] == "remediated"
    assert row["reason"] == "suggested-catalog-latest"
    assert ("remediated", None, "1.0.0") in calls
    assert ("remediated", "latest", None) in calls


def test_both_catalogs_miss_stays_missing() -> None:
    def resolve(*_a, **_kw):
        return None

    row = _run(_dep(catalog="remediated", version="1.0.0"), resolve)
    assert row["action"] == "MISSING"
    assert row["to"] is None
    assert row["reason"] == "no-lightwell-metadata"


def test_latest_not_newer_keeps() -> None:
    def resolve(catalog, g, a, *, tag, same_base_current, **_kw):
        if same_base_current is not None:
            return None
        if catalog == "remediated" and tag == "latest":
            return "0.9.0"
        if catalog == "validated" and tag == "latest":
            return None
        return None

    row = _run(_dep(catalog="remediated", version="1.0.0"), resolve)
    assert row["action"] == "KEEP"
    assert row["reason"] == "candidate-not-newer"
    assert row["candidate"] == "0.9.0"
    assert row["to"] == "1.0.0"
    assert row["catalog"] == "remediated"


def test_unresolved_property_is_missing() -> None:
    row = _run(_dep(version="${json.version}"), lambda *_a, **_k: "1.0.0")
    assert row["action"] == "MISSING"
    assert row["reason"] == "unresolved-version"


def test_keep_when_target_equals_current() -> None:
    def resolve(catalog, g, a, *, tag, same_base_current, **_kw):
        if catalog == "remediated" and same_base_current == "1.2.3":
            return "1.2.3"
        raise AssertionError("unexpected resolve")

    row = _run(_dep(catalog="remediated", version="1.2.3"), resolve)
    assert row["action"] == "KEEP"
    assert row["to"] == "1.2.3"


def test_validated_latest_hit_asks_on_minor() -> None:
    def resolve(catalog, g, a, *, tag, same_base_current, **_kw):
        if catalog == "validated" and tag == "latest":
            return "2.0.0"
        raise AssertionError(f"unexpected resolve: {catalog=} {tag=}")

    row = _run(_dep(catalog="validated", version="1.0.0"), resolve)
    assert row["action"] == "ASK"
    assert row["reason"] == "semver-major"
    assert row["to"] == "2.0.0"


def test_unknown_catalog_prefers_remediated_same_base() -> None:
    def resolve(catalog, g, a, *, tag, same_base_current, **_kw):
        if catalog == "remediated" and same_base_current == "1.2.3":
            return "1.2.3.rhlw-00009"
        raise AssertionError(f"unexpected resolve: {catalog=} {tag=} {same_base_current=}")

    row = _run(_dep(catalog="unknown", version="1.2.3"), resolve)
    assert row["action"] == "UPGRADE"
    assert row["catalog"] == "remediated"
    assert row["to"] == "1.2.3.rhlw-00009"


def test_take_latest_auto_upgrades_minor() -> None:
    def resolve(catalog, g, a, *, tag, same_base_current, **_kw):
        if catalog == "validated" and tag == "latest":
            return "1.1.0"
        raise AssertionError("unexpected resolve")

    row = _run(_dep(catalog="validated", version="1.0.0"), resolve, take_latest=True)
    assert row["action"] == "UPGRADE"
    assert row["to"] == "1.1.0"


def test_suggested_catalog_latest_never_upgrades_with_take_latest() -> None:
    def resolve(catalog, g, a, *, tag, same_base_current, **_kw):
        if same_base_current is not None:
            return None
        if catalog == "remediated" and tag == "latest":
            return "9.0.0.rhlw-00001"
        return None

    row = _run(_dep(catalog="remediated", version="1.0.0"), resolve, take_latest=True)
    assert row["action"] == "ASK"
    assert row["reason"] == "suggested-catalog-latest"


def test_validated_primary_miss_tries_remediated_latest_only() -> None:
    calls: list[tuple] = []

    def resolve(catalog, g, a, *, tag, same_base_current, **_kw):
        calls.append((catalog, tag, same_base_current))
        if catalog == "validated" and tag == "latest":
            return None
        if catalog == "remediated" and tag == "latest":
            return "3.1.0.rhlw-00002"
        raise AssertionError(f"unexpected resolve: {catalog=} {tag=} {same_base_current=}")

    row = _run(_dep(catalog="validated", version="1.0.0"), resolve)
    assert row["action"] == "ASK"
    assert row["reason"] == "suggested-catalog-latest"
    assert row["catalog"] == "remediated"
    assert row["to"] == "3.1.0.rhlw-00002"
    assert calls.count(("validated", "latest", None)) == 1
    assert ("remediated", "latest", None) in calls
