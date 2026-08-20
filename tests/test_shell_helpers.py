"""Shell helper tests. Never prints credential values."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

from _paths import ADD_OSV_SCRIPTS, SHARED_SCRIPTS


def _bash(
    script: str,
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(
        ["bash", "-c", script],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd else None,
        env=merged,
    )


def test_load_creds_from_env_skips_file() -> None:
    load = SHARED_SCRIPTS / "_load-creds.sh"
    proc = _bash(
        f'source "{load}" && echo CREDS_OK',
        env={
            "LIGHTWELL_USERNAME": "from-env",
            "LIGHTWELL_TOKEN": "from-env-token",
        },
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "CREDS_OK"
    assert "from-env-token" not in proc.stdout
    assert "from-env-token" not in proc.stderr


def test_load_creds_missing_file(tmp_path: Path) -> None:
    load = SHARED_SCRIPTS / "_load-creds.sh"
    proc = _bash(
        f'source "{load}"',
        cwd=tmp_path,
        env={"LIGHTWELL_USERNAME": "", "LIGHTWELL_TOKEN": ""},
    )
    assert proc.returncode == 1
    assert "CREDS_FILE_MISSING" in proc.stderr


def test_load_creds_from_temp_repo_file(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "_creds.sh").write_text(
        "LIGHTWELL_USERNAME=fixture-user\nLIGHTWELL_TOKEN=fixture-token\n",
        encoding="utf-8",
    )
    load = SHARED_SCRIPTS / "_load-creds.sh"
    proc = _bash(
        f'source "{load}" && echo CREDS_OK',
        cwd=tmp_path,
        env={
            "LIGHTWELL_USERNAME": "",
            "LIGHTWELL_TOKEN": "",
            "GIT_DIR": str(tmp_path / ".not-a-git-dir"),
        },
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "CREDS_OK"
    assert "fixture-token" not in proc.stdout
    assert "fixture-token" not in proc.stderr


def test_repo_root_walks_to_pom(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text("<project/>", encoding="utf-8")
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    repo = SHARED_SCRIPTS / "_repo.sh"
    proc = _bash(
        f'source "{repo}" && lightwell_repo_root "{nested}"',
        env={"GIT_DIR": str(tmp_path / ".not-a-git-dir")},
    )
    assert proc.returncode == 0, proc.stderr
    assert Path(proc.stdout.strip()) == tmp_path


def test_process_renovate_help() -> None:
    script = ADD_OSV_SCRIPTS / "process-renovate-prs.sh"
    proc = subprocess.run(
        ["bash", str(script), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "Usage:" in proc.stderr


def test_process_renovate_unknown_option() -> None:
    script = ADD_OSV_SCRIPTS / "process-renovate-prs.sh"
    proc = subprocess.run(
        ["bash", str(script), "--nope"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "unknown option" in proc.stderr


def test_process_renovate_missing_gh(tmp_path: Path) -> None:
    # GitHub-hosted runners ship gh in /usr/bin, so PATH=/usr/bin:/bin still
    # finds it. Use a PATH that has dirname (needed to resolve the script)
    # but not gh.
    script = ADD_OSV_SCRIPTS / "process-renovate-prs.sh"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    dirname = shutil.which("dirname")
    assert dirname is not None
    os.symlink(dirname, bin_dir / "dirname")
    bash = shutil.which("bash") or "/bin/bash"
    proc = subprocess.run(
        [bash, str(script)],
        check=False,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PATH": str(bin_dir),
            "LIGHTWELL_USERNAME": "u",
            "LIGHTWELL_TOKEN": "t",
        },
    )
    assert proc.returncode == 1, proc.stderr
    assert "ERROR_GH_MISSING" in proc.stderr


def test_process_renovate_empty_pr_list(tmp_path: Path) -> None:
    script = ADD_OSV_SCRIPTS / "process-renovate-prs.sh"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh = bin_dir / "gh"
    jq = bin_dir / "jq"
    gh.write_text("#!/bin/bash\necho '[]'\n", encoding="utf-8")
    jq.write_text("#!/bin/bash\necho 0\n", encoding="utf-8")
    gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
    jq.chmod(jq.stat().st_mode | stat.S_IEXEC)
    proc = subprocess.run(
        ["bash", str(script)],
        check=False,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
            "LIGHTWELL_USERNAME": "u",
            "LIGHTWELL_TOKEN": "t",
        },
    )
    assert proc.returncode == 0, proc.stderr
    assert "NO_OPEN_RENOVATE_PRS" in proc.stdout
