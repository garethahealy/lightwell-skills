"""Canonical packages.redhat.com content URLs for the Lightwell catalog.

Console: https://console.redhat.com/lightwell
Content root: …/api/pulp-content/lightwell/
"""

from __future__ import annotations

import os

# Override content root (trailing slash optional).
CONTENT_ROOT = os.environ.get(
    "LIGHTWELL_CONTENT_ROOT",
    "https://packages.redhat.com/api/pulp-content/lightwell",
).rstrip("/")

SOURCE_URL = {
    "remediated": f"{CONTENT_ROOT}/java/remediated/",
    "validated": f"{CONTENT_ROOT}/java/validated/",
}

OSV_REMEDIATED_BASE = f"{CONTENT_ROOT}/osv/java/remediated"

DEFAULT_API_ROOT = "https://console.redhat.com/api/lightwell/v0.1"

DEFAULT_SSO_TOKEN_URL = "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"


def api_root() -> str:
    """Lightwell API v0.1 base. Override with ``LIGHTWELL_API_ROOT``."""
    return os.environ.get("LIGHTWELL_API_ROOT", DEFAULT_API_ROOT).rstrip("/")


def sso_token_url() -> str:
    """Client-credentials token endpoint. Override with ``LIGHTWELL_SSO_TOKEN_URL``."""
    return os.environ.get("LIGHTWELL_SSO_TOKEN_URL", DEFAULT_SSO_TOKEN_URL).strip()


def java_catalog_base(catalog: str) -> str:
    """Return trailing-slash base URL for a java catalog (remediated|validated)."""
    return SOURCE_URL.get(catalog) or SOURCE_URL["remediated"]


def maven_metadata_url(catalog: str, group_id: str, artifact_id: str) -> str:
    group_path = group_id.replace(".", "/")
    return f"{java_catalog_base(catalog)}{group_path}/{artifact_id}/maven-metadata.xml"


def provenance_bundle_url(catalog: str, group_id: str, artifact_id: str, version: str) -> str:
    """URL for `{artifact}-{version}.provenance.sigstore.json`."""
    group_path = group_id.replace(".", "/")
    name = f"{artifact_id}-{version}.provenance.sigstore.json"
    return f"{java_catalog_base(catalog)}{group_path}/{artifact_id}/{version}/{name}"


def sbom_filename(artifact_id: str, version: str) -> str:
    """`{artifactId}-{version}.cyclonedx.json` next to the jar."""
    return f"{artifact_id}-{version}.cyclonedx.json"


def sbom_url(catalog: str, group_id: str, artifact_id: str, version: str) -> str:
    """URL for `{artifactId}-{version}.cyclonedx.json` next to the jar."""
    group_path = group_id.replace(".", "/")
    name = sbom_filename(artifact_id, version)
    return f"{java_catalog_base(catalog)}{group_path}/{artifact_id}/{version}/{name}"
