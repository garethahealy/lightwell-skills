"""Canonical packages.redhat.com content URLs for the Lightwell demo catalog.

Demo console: https://console.redhat.com/lightwell/demo
Content root: …/api/pulp-content/public-lightwell-demo/
"""

from __future__ import annotations

import os

# Override for non-demo environments (trailing slash optional).
CONTENT_ROOT = os.environ.get(
    "LIGHTWELL_CONTENT_ROOT",
    "https://packages.redhat.com/api/pulp-content/public-lightwell-demo",
).rstrip("/")

SOURCE_URL = {
    "remediated": f"{CONTENT_ROOT}/java/remediated/",
    "validated": f"{CONTENT_ROOT}/java/validated/",
}

OSV_REMEDIATED_BASE = f"{CONTENT_ROOT}/osv/java/remediated"


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
