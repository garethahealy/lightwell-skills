"""CLI tests for skill phase scripts (plan / apply / summary)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from _paths import FIXTURES, UPGRADE_DIRECTS_SCRIPTS, UPGRADE_TRANSITIVES_SCRIPTS
from lightwell_shared import SCHEMA_VERSION


def _run(script: Path, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script), *args],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd else None,
    )


def test_directs_plan_cli_writes_json(tmp_path: Path) -> None:
    pom = FIXTURES / "sample_pom.xml"
    out = tmp_path / "plan.json"
    proc = _run(
        UPGRADE_DIRECTS_SCRIPTS / "plan.py",
        "--pom",
        str(pom),
        "-o",
        str(out),
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schemaVersion"] == SCHEMA_VERSION
    gas = {d["ga"] for d in data["dependencies"]}
    assert "org.json:json" in gas
    assert any(p["ga"] == "commons-io:commons-io" for p in data["promotedSkipped"])


def test_directs_plan_cli_missing_pom(tmp_path: Path) -> None:
    proc = _run(
        UPGRADE_DIRECTS_SCRIPTS / "plan.py",
        "--pom",
        str(tmp_path / "nope.xml"),
    )
    assert proc.returncode == 2
    assert "pom not found" in proc.stderr


def test_directs_apply_dry_run_cli(tmp_path: Path) -> None:
    pom = tmp_path / "pom.xml"
    pom.write_text((FIXTURES / "sample_pom.xml").read_text(encoding="utf-8"), encoding="utf-8")
    collect = {
        "schemaVersion": SCHEMA_VERSION,
        "pom": str(pom),
        "results": [
            {
                "action": "UPGRADE",
                "ga": "org.json:json",
                "groupId": "org.json",
                "artifactId": "json",
                "from": "20220320",
                "to": "20220320.0.0.rhlw-00003",
                "catalog": "remediated",
                "property": "json.version",
            }
        ],
    }
    collect_path = tmp_path / "collect.json"
    collect_path.write_text(json.dumps(collect), encoding="utf-8")
    out = tmp_path / "apply.json"
    proc = _run(
        UPGRADE_DIRECTS_SCRIPTS / "apply.py",
        "--from-collect",
        str(collect_path),
        "--dry-run",
        "--skip-build",
        "-o",
        str(out),
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["dryRun"] is True
    assert data["applied"][0]["to"] == "20220320.0.0.rhlw-00003"
    # dry-run must not rewrite the pom
    assert "rhlw-00003" not in pom.read_text(encoding="utf-8")


def test_directs_summary_cli_skip_osv(tmp_path: Path) -> None:
    collect = {
        "schemaVersion": SCHEMA_VERSION,
        "pom": "pom.xml",
        "results": [
            {
                "action": "UPGRADE",
                "ga": "org.json:json",
                "from": "20220320",
                "to": "20220320.0.0.rhlw-00003",
                "catalog": "remediated",
            }
        ],
    }
    apply = {
        "schemaVersion": SCHEMA_VERSION,
        "applied": [
            {
                "action": "UPGRADE",
                "appliedAction": "UPGRADE",
                "ga": "org.json:json",
                "groupId": "org.json",
                "artifactId": "json",
                "from": "20220320",
                "to": "20220320.0.0.rhlw-00003",
                "catalog": "remediated",
            }
        ],
        "skipped": [],
    }
    collect_path = tmp_path / "collect.json"
    apply_path = tmp_path / "apply.json"
    md_path = tmp_path / "summary.md"
    collect_path.write_text(json.dumps(collect), encoding="utf-8")
    apply_path.write_text(json.dumps(apply), encoding="utf-8")
    proc = _run(
        UPGRADE_DIRECTS_SCRIPTS / "summary.py",
        "--from-collect",
        str(collect_path),
        "--from-apply",
        str(apply_path),
        "--skip-osv",
        "-o",
        str(md_path),
    )
    assert proc.returncode == 0, proc.stderr
    text = md_path.read_text(encoding="utf-8")
    assert "Upgrade directs summary" in text
    assert "org.json:json" in text


def _write_settings(root: Path) -> None:
    dest = root / ".m2" / "settings.xml"
    dest.parent.mkdir(parents=True)
    dest.write_text("<settings/>\n", encoding="utf-8")


def test_transitives_plan_cli_tree_file(tmp_path: Path) -> None:
    pom = tmp_path / "pom.xml"
    pom.write_text((FIXTURES / "sample_pom.xml").read_text(encoding="utf-8"), encoding="utf-8")
    _write_settings(tmp_path)
    out = tmp_path / "plan.json"
    proc = _run(
        UPGRADE_TRANSITIVES_SCRIPTS / "plan.py",
        "--pom",
        str(pom),
        "--tree-file",
        str(FIXTURES / "tree.txt"),
        "-o",
        str(out),
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schemaVersion"] == SCHEMA_VERSION
    assert any(c["ga"] == "org.yaml:snakeyaml" for c in data["candidates"])


def test_transitives_plan_cli_missing_pom(tmp_path: Path) -> None:
    proc = _run(
        UPGRADE_TRANSITIVES_SCRIPTS / "plan.py",
        "--pom",
        str(tmp_path / "nope.xml"),
    )
    assert proc.returncode == 2
    assert "pom not found" in proc.stderr


def test_transitives_apply_dry_run_cli(tmp_path: Path) -> None:
    pom = tmp_path / "pom.xml"
    original = (FIXTURES / "sample_pom.xml").read_text(encoding="utf-8")
    pom.write_text(original, encoding="utf-8")
    collect = {
        "schemaVersion": SCHEMA_VERSION,
        "pom": str(pom),
        "results": [
            {
                "action": "PROMOTE",
                "ga": "org.yaml:snakeyaml",
                "groupId": "org.yaml",
                "artifactId": "snakeyaml",
                "from": "2.0",
                "to": "2.0.0.rhlw-00001",
                "catalog": "remediated",
                "via": ["com.fasterxml.jackson.dataformat:jackson-dataformat-yaml"],
            }
        ],
    }
    collect_path = tmp_path / "collect.json"
    collect_path.write_text(json.dumps(collect), encoding="utf-8")
    out = tmp_path / "apply.json"
    proc = _run(
        UPGRADE_TRANSITIVES_SCRIPTS / "apply.py",
        "--from-collect",
        str(collect_path),
        "--dry-run",
        "--skip-build",
        "-o",
        str(out),
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["dryRun"] is True
    assert data["applied"][0]["action"] == "PROMOTE"
    assert pom.read_text(encoding="utf-8") == original


def test_transitives_summary_cli_skip_osv(tmp_path: Path) -> None:
    collect = {
        "schemaVersion": SCHEMA_VERSION,
        "pom": "pom.xml",
        "results": [
            {
                "action": "PROMOTE",
                "ga": "org.yaml:snakeyaml",
                "from": "2.0",
                "to": "2.0.0.rhlw-00001",
                "via": ["com.fasterxml.jackson.dataformat:jackson-dataformat-yaml"],
            }
        ],
    }
    apply = {
        "schemaVersion": SCHEMA_VERSION,
        "applied": [
            {
                "action": "PROMOTE",
                "appliedAction": "PROMOTE",
                "ga": "org.yaml:snakeyaml",
                "groupId": "org.yaml",
                "artifactId": "snakeyaml",
                "from": "2.0",
                "to": "2.0.0.rhlw-00001",
            }
        ],
        "skipped": [],
    }
    collect_path = tmp_path / "collect.json"
    apply_path = tmp_path / "apply.json"
    md_path = tmp_path / "summary.md"
    collect_path.write_text(json.dumps(collect), encoding="utf-8")
    apply_path.write_text(json.dumps(apply), encoding="utf-8")
    proc = _run(
        UPGRADE_TRANSITIVES_SCRIPTS / "summary.py",
        "--from-collect",
        str(collect_path),
        "--from-apply",
        str(apply_path),
        "--skip-osv",
        "-o",
        str(md_path),
    )
    assert proc.returncode == 0, proc.stderr
    text = md_path.read_text(encoding="utf-8")
    assert "Upgrade transitives summary" in text
    assert "org.yaml:snakeyaml" in text
