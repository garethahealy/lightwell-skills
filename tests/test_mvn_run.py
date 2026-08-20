"""Unit tests for mvn_run helpers that do not invoke Maven."""

from __future__ import annotations

import os
from unittest.mock import patch

from lightwell_shared.mvn_run import lightwell_download_lines, maven_argv, maven_binary


def test_lightwell_download_lines() -> None:
    log = """\
Downloaded from central: https://repo.maven.apache.org/maven2/junit/junit/4.13.2/junit-4.13.2.jar
Downloaded from lightwell-remediated: https://packages.redhat.com/api/pulp-content/public-lightwell-demo/java/remediated/org/json/json/1/json-1.jar
Downloaded from lightwell-validated: https://packages.redhat.com/api/pulp-content/public-lightwell-demo/java/validated/com/fasterxml/jackson/dataformat/jackson-dataformat-yaml/2.19.4/jackson-dataformat-yaml-2.19.4.jar
"""
    lines = lightwell_download_lines(log)
    assert len(lines) == 2
    assert all("lightwell-" in ln for ln in lines)
    assert lightwell_download_lines("no downloads") == []


def test_maven_argv_flags() -> None:
    with patch.dict(os.environ, {"LIGHTWELL_MVN": "mvn"}, clear=False):
        maven_binary.cache_clear()
        argv = maven_argv("clean", "install", "--settings=.m2/settings.xml")
        assert argv[0] == "mvn"
        assert "--batch-mode" in argv
        assert "--no-transfer-progress" in argv
        assert "clean" in argv
        maven_binary.cache_clear()
