"""Unit tests for upgrade-transitives decide_actions."""

from __future__ import annotations

from lightwell_shared.transitives_collect import MetaResult, decide_actions, format_plain


def _plan(**kwargs):
    base = {"promoted": [], "candidates": []}
    base.update(kwargs)
    return base


def _promoted(**kwargs):
    row = {
        "ga": "commons-io:commons-io",
        "groupId": "commons-io",
        "artifactId": "commons-io",
        "treeVersion": "2.11.0.rhlw-00001",
        "viaParents": ["commons-fileupload:commons-fileupload"],
    }
    row.update(kwargs)
    return row


def _cand(**kwargs):
    row = {
        "ga": "org.yaml:snakeyaml",
        "groupId": "org.yaml",
        "artifactId": "snakeyaml",
        "treeVersion": "2.0",
        "viaParents": ["com.fasterxml.jackson.dataformat:jackson-dataformat-yaml"],
    }
    row.update(kwargs)
    return row


def _by_ga(rows: list[dict]) -> dict[str, dict]:
    return {r["ga"]: r for r in rows}


def test_drop_gone_and_native() -> None:
    plan = _plan(promoted=[_promoted()])
    meta = {"commons-io:commons-io": MetaResult(ok=True, version="2.11.0.rhlw-00002")}
    gone = decide_actions(
        plan,
        meta,
        {"commons-io:commons-io": {"commons-fileupload:commons-fileupload": "ABSENT"}},
    )
    assert _by_ga(gone)["commons-io:commons-io"]["action"] == "DROP"
    assert _by_ga(gone)["commons-io:commons-io"]["reason"] == "gone"

    native = decide_actions(
        plan,
        meta,
        {"commons-io:commons-io": {"commons-fileupload:commons-fileupload": "2.11.0.rhlw-00002"}},
    )
    assert _by_ga(native)["commons-io:commons-io"]["reason"] == "native"


def test_update_keep_ask() -> None:
    plan = _plan(promoted=[_promoted(treeVersion="2.11.0.rhlw-00001")])
    update = decide_actions(
        plan,
        {"commons-io:commons-io": MetaResult(ok=True, version="2.11.0.rhlw-00002")},
        {},
    )
    assert _by_ga(update)["commons-io:commons-io"]["action"] == "UPDATE"

    keep_same = decide_actions(
        plan,
        {"commons-io:commons-io": MetaResult(ok=True, version="2.11.0.rhlw-00001")},
        {},
    )
    assert _by_ga(keep_same)["commons-io:commons-io"]["action"] == "KEEP"

    older = decide_actions(
        plan,
        {"commons-io:commons-io": MetaResult(ok=True, version="2.10.0.rhlw-00099")},
        {},
    )
    assert _by_ga(older)["commons-io:commons-io"]["action"] == "KEEP"
    assert _by_ga(older)["commons-io:commons-io"]["reason"] == "candidate-not-newer"

    ask = decide_actions(
        plan,
        {"commons-io:commons-io": MetaResult(ok=True, version="2.12.0.rhlw-00001")},
        {},
    )
    row = _by_ga(ask)["commons-io:commons-io"]
    assert row["action"] == "ASK"
    assert row["pending"] == "UPDATE"
    assert row["reason"] == "semver-minor"


def test_keep_existing_rhlw_when_meta_missing() -> None:
    plan = _plan(promoted=[_promoted()])
    rows = decide_actions(plan, {"commons-io:commons-io": MetaResult(ok=False, error="MISSING")}, {})
    assert _by_ga(rows)["commons-io:commons-io"]["action"] == "KEEP"


def test_drop_stale_parent_without_rhlw() -> None:
    plan = _plan(promoted=[_promoted(treeVersion="2.11.0")])
    rows = decide_actions(plan, {"commons-io:commons-io": MetaResult(ok=False, error="MISSING")}, {})
    assert _by_ga(rows)["commons-io:commons-io"]["action"] == "DROP"
    assert _by_ga(rows)["commons-io:commons-io"]["reason"] == "stale-parent"


def test_promote_and_skip_already_promoted_candidate() -> None:
    plan = _plan(
        promoted=[_promoted()],
        candidates=[_cand(), _cand(ga="commons-io:commons-io")],
    )
    meta = {
        "org.yaml:snakeyaml": MetaResult(ok=True, version="2.0.rhlw-00002"),
        "commons-io:commons-io": MetaResult(ok=True, version="2.11.0.rhlw-00002"),
    }
    rows = decide_actions(plan, meta, {})
    by = _by_ga(rows)
    assert by["org.yaml:snakeyaml"]["action"] == "PROMOTE"
    # already in promoted list — candidate loop skipped (UPDATE path instead)
    assert by["commons-io:commons-io"]["action"] == "UPDATE"


def test_promote_ask_on_minor() -> None:
    plan = _plan(candidates=[_cand(treeVersion="1.0.0")])
    rows = decide_actions(
        plan,
        {"org.yaml:snakeyaml": MetaResult(ok=True, version="1.1.0.rhlw-00001")},
        {},
    )
    row = _by_ga(rows)["org.yaml:snakeyaml"]
    assert row["action"] == "ASK"
    assert row["pending"] == "PROMOTE"


def test_take_latest_promotes_minor() -> None:
    plan = _plan(candidates=[_cand(treeVersion="1.0.0")])
    rows = decide_actions(
        plan,
        {"org.yaml:snakeyaml": MetaResult(ok=True, version="1.1.0.rhlw-00001")},
        {},
        take_latest=True,
    )
    assert _by_ga(rows)["org.yaml:snakeyaml"]["action"] == "PROMOTE"


def test_format_plain() -> None:
    text = format_plain(
        [
            {
                "action": "PROMOTE",
                "ga": "g:a",
                "from": "1",
                "to": "1.rhlw-00001",
                "via": ["p:q"],
            }
        ]
    )
    assert "PROMOTE g:a 1 -> 1.rhlw-00001 via p:q" in text
