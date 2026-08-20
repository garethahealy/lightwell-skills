"""Shared Maven invoke + repo root helpers for upgrade apply scripts.

Prefers Maven Daemon (`mvnd`) when on PATH for faster repeated invokes.
Override binary with LIGHTWELL_MVN (e.g. mvn or /usr/bin/mvnd).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def maven_binary() -> str:
    """Return mvnd or mvn executable name/path."""
    override = os.environ.get("LIGHTWELL_MVN", "").strip()
    if override:
        return override
    for candidate in ("mvnd", "mvn"):
        if shutil.which(candidate):
            return candidate
    return "mvn"


def maven_argv(*extra: str) -> list[str]:
    """Build a Maven/mvnd argv with standard Lightwell flags."""
    return [
        maven_binary(),
        "--batch-mode",
        "--no-transfer-progress",
        *extra,
    ]


def repo_root_for(start: Path) -> Path:
    """Return git toplevel containing start, else start's directory (or self if dir)."""
    base = start if start.is_dir() else start.parent
    try:
        out = subprocess.run(
            ["git", "-C", str(base), "rev-parse", "--show-toplevel"],
            check=False,
            capture_output=True,
            text=True,
        )
        if out.returncode == 0 and out.stdout.strip():
            return Path(out.stdout.strip())
    except OSError:
        pass
    return base.resolve()


def run_mvn(
    args: list[str],
    *,
    cwd: Path,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run maven_binary() with --batch-mode --no-transfer-progress + args."""
    return subprocess.run(
        maven_argv(*args),
        check=check,
        capture_output=True,
        text=True,
        cwd=str(cwd),
    )


def run_dependency_tree(
    *,
    repo_root: Path,
    settings: str,
    pom: Path | str,
    output_file: Path,
) -> subprocess.CompletedProcess[str]:
    """Run dependency:tree writing text output to output_file."""
    return run_mvn(
        [
            "-q",
            f"-f={pom}",
            "dependency:tree",
            f"--settings={settings}",
            f"-DoutputFile={output_file}",
            "-DoutputType=text",
        ],
        cwd=repo_root,
    )


def run_mvn_clean_install(
    repo_root: Path,
    settings: str = ".m2/settings.xml",
) -> tuple[int, str]:
    """Run mvn/mvnd clean install; return (exit_code, combined output)."""
    proc = run_mvn(
        [
            "clean",
            "install",
            f"--settings={settings}",
        ],
        cwd=repo_root,
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, out


def lightwell_download_lines(log: str) -> list[str]:
    lines = []
    for line in log.splitlines():
        if "Downloaded from lightwell-remediated:" in line or ("Downloaded from lightwell-validated:" in line):
            lines.append(line.strip())
    return lines


def resolve_local_repo(repo_root: Path, settings: str) -> Path | None:
    """Resolve settings.localRepository via help:evaluate (mvn/mvnd)."""
    proc = run_mvn(
        [
            f"--settings={settings}",
            "help:evaluate",
            "-Dexpression=settings.localRepository",
            "-DforceStdout",
        ],
        cwd=repo_root,
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    path = ""
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("["):
            continue
        path = line
    path = path.strip().strip("\r")
    if not path or "null" in path:
        return None
    return Path(path)
