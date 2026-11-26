"""Maven ComparableVersion order used for synthetic latest/release tags."""

from __future__ import annotations

from lightwell_shared.maven_version import compare_versions, highest_version, release_version


def test_maven_qualifiers_and_equality() -> None:
    order = [
        "1.0-alpha",
        "1.0-beta",
        "1.0-milestone",
        "1.0-rc",
        "1.0-snapshot",
        "1.0",
        "1.0-sp",
    ]
    for earlier, later in zip(order, order[1:], strict=False):
        assert compare_versions(earlier, later) < 0, (earlier, later)
    assert compare_versions("1", "1.0.0") == 0
    assert compare_versions("1.0-ga", "1") == 0
    assert compare_versions("1.0-final", "1.0") == 0
    assert compare_versions("1.0-release", "1.0.0") == 0


def test_rhlw_orders_as_maven_rebuild() -> None:
    assert compare_versions("1.0.0.rhlw-00001", "1.0.0.rhlw-00002") < 0
    assert compare_versions("1.0.0.rhlw-00009", "1.0.0.rhlw-00010") < 0
    assert compare_versions("20220320", "20220320.0.0.rhlw-00003") < 0
    assert highest_version(["20220320", "20220320.0.0.rhlw-00001", "20220320.0.0.rhlw-00003"]) == (
        "20220320.0.0.rhlw-00003"
    )


def test_release_skips_snapshot_when_a_release_exists() -> None:
    versions = ["1.2.4", "1.2.5-SNAPSHOT"]
    assert highest_version(versions) == "1.2.5-SNAPSHOT"
    assert release_version(versions) == "1.2.4"
