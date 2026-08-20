"""Interpreter and PATH preflight for Lightwell CLIs.

Skill scripts still insert ``lightwell-shared/scripts`` on ``sys.path`` (they
live outside this package). After that, call ``require_python()``.
"""

from __future__ import annotations

import shutil
import sys

MIN_PYTHON = (3, 14)


def require_python(*, minimum: tuple[int, int] = MIN_PYTHON) -> None:
    """Exit 2 if the interpreter is older than the skill pin (Python 3.14+)."""
    if sys.version_info[:2] < minimum:
        need = ".".join(str(p) for p in minimum)
        got = ".".join(str(p) for p in sys.version_info[:3])
        print(
            f"error: Python {need}+ required (this interpreter is {got})",
            file=sys.stderr,
        )
        raise SystemExit(2)


def missing_binaries(*names: str) -> list[str]:
    """Return executable names that are not on PATH."""
    return [name for name in names if shutil.which(name) is None]


def preflight(
    *,
    maven: bool = False,
    cosign: bool = False,
    jq: bool = False,
    gh: bool = False,
) -> list[str]:
    """Return missing tools. Maven accepts mvnd or mvn (or LIGHTWELL_MVN)."""
    from lightwell_shared.mvn_run import maven_binary

    missing: list[str] = []
    if maven:
        binary = maven_binary()
        if shutil.which(binary) is None:
            missing.append(binary)
    if cosign:
        missing.extend(missing_binaries("cosign"))
    if jq:
        missing.extend(missing_binaries("jq"))
    if gh:
        missing.extend(missing_binaries("gh"))
    return missing


def print_preflight_errors(missing: list[str]) -> None:
    if missing:
        print(
            "error: required binary missing on PATH: " + ", ".join(missing),
            file=sys.stderr,
        )
