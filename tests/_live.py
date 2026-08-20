"""Live Lightwell demo catalog helpers. Never prints credentials."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from _paths import FIXTURES
from lightwell_shared.mvn_run import maven_binary

DEMO_JSON_G = "org.json"
DEMO_JSON_A = "json"
DEMO_JSON_BASE = "20220320"


def require_lightwell_creds() -> tuple[str, str]:
    user = os.environ.get("LIGHTWELL_USERNAME", "").strip()
    token = os.environ.get("LIGHTWELL_TOKEN", "").strip()
    if not user or not token:
        raise RuntimeError("LIGHTWELL_USERNAME and LIGHTWELL_TOKEN required for demo-catalog tests")
    return user, token


def require_on_path(*names: str) -> str:
    """Return the first executable name that exists on PATH."""
    for name in names:
        if shutil.which(name):
            return name
    raise RuntimeError("required binary missing on PATH: " + ", ".join(names))


def require_mvn() -> str:
    binary = maven_binary()
    if not shutil.which(binary):
        raise RuntimeError(f"required binary missing on PATH: {binary}")
    return binary


def require_cosign() -> str:
    return require_on_path("cosign")


def fixture_pom() -> Path:
    return FIXTURES / "consumer" / "pom.xml"


def write_maven_settings(dest: Path, *, local_repo: Path) -> Path:
    """Write settings.xml that uses env Lightwell creds (no secrets in the file)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        f"""<?xml version="1.0" encoding="UTF-8"?>
<settings>
  <localRepository>{local_repo}</localRepository>
  <servers>
    <server>
      <id>lightwell-remediated</id>
      <username>${{env.LIGHTWELL_USERNAME}}</username>
      <password>${{env.LIGHTWELL_TOKEN}}</password>
    </server>
    <server>
      <id>lightwell-validated</id>
      <username>${{env.LIGHTWELL_USERNAME}}</username>
      <password>${{env.LIGHTWELL_TOKEN}}</password>
    </server>
  </servers>
  <profiles>
    <profile>
      <id>lightwell</id>
      <repositories>
        <repository>
          <id>lightwell-remediated</id>
          <url>https://packages.redhat.com/api/pulp-content/public-lightwell-demo/java/remediated/</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>false</enabled></snapshots>
        </repository>
        <repository>
          <id>lightwell-validated</id>
          <url>https://packages.redhat.com/api/pulp-content/public-lightwell-demo/java/validated/</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>false</enabled></snapshots>
        </repository>
      </repositories>
    </profile>
  </profiles>
  <activeProfiles>
    <activeProfile>lightwell</activeProfile>
  </activeProfiles>
</settings>
""",
        encoding="utf-8",
    )
    return dest
