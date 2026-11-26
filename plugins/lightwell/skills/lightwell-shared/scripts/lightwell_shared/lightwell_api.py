"""Lightwell API v0.1 client for catalog version lists and advisories.

Auth uses ``LIGHTWELL_USERNAME`` / ``LIGHTWELL_TOKEN``. The console gateway is
probed with ``Authorization: Bearer``, then HTTP Basic. The first form that
``GET /terms/required`` accepts is reused for the process.

Jar bytes, provenance bundles, and CycloneDX SBOMs stay on packages.redhat.com.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from html import escape
from typing import Any
from urllib.parse import quote, unquote, urlencode

from lightwell_shared.download_http import HttpAuthError
from lightwell_shared.http_pool import HttpFetchError, basic_auth_header, shared_https_pool
from lightwell_shared.lightwell_urls import api_root, java_catalog_base
from lightwell_shared.maven_version import highest_version, release_version

_NO_STORE_HEADERS = {
    "Accept": "application/json",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}
_PAGE_LIMIT = 100
_MAX_PAGES = 500

Transport = Callable[[str, dict[str, str]], tuple[int, str, dict[str, str]]]

_state_lock = threading.Lock()
_auth_headers: dict[tuple[str, str, str], dict[str, str]] = {}
_repositories: dict[tuple[str, str, str, str], dict[str, Any]] = {}
_transport_override: Transport | None = None


class ApiError(Exception):
    """Lightwell API returned a response the client cannot use."""


class PackageNotFound(ApiError):
    """Catalog object was HTTP 404."""


class TermsRequiredError(RuntimeError):
    """HTTP 428 or ``terms.required`` — stop the phase. Do not treat as a miss."""

    def __init__(self) -> None:
        super().__init__("TERMS_REQUIRED: accept Lightwell terms before continuing")


def clear_state() -> None:
    """Drop process caches. Tests use this between cases."""
    global _transport_override
    with _state_lock:
        _auth_headers.clear()
        _repositories.clear()
        _transport_override = None


def set_transport(transport: Transport | None) -> None:
    """Replace the HTTPS transport. ``None`` restores the shared pool."""
    global _transport_override
    with _state_lock:
        _transport_override = transport


def _transport() -> Transport:
    with _state_lock:
        override = _transport_override
    if override is not None:
        return override
    return _pool_transport


def _pool_transport(url: str, headers: dict[str, str]) -> tuple[int, str, dict[str, str]]:
    try:
        return shared_https_pool().request(url, headers=headers, method="GET")
    except HttpFetchError as exc:
        raise ApiError(f"API_FETCH_FAILED: {exc}") from exc


def _request_headers(authorization: str) -> dict[str, str]:
    headers = dict(_NO_STORE_HEADERS)
    headers["Authorization"] = authorization
    return headers


def _terms_decision(status: int, body: str) -> bool | None:
    """True when this scheme is accepted, False to try the next, None when terms block."""
    if status == 428:
        return None
    if status != 200:
        return False
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return False
    if isinstance(data, dict) and data.get("required") is True:
        return None
    return True


def _ensure_auth(username: str, token: str) -> dict[str, str]:
    root = api_root()
    key = (root, username, token)
    with _state_lock:
        cached = _auth_headers.get(key)
    if cached is not None:
        return dict(cached)

    url = f"{root}/terms/required"
    schemes = (
        f"Bearer {token}",
        basic_auth_header(username, token),
    )
    denials: list[int] = []
    other: list[int] = []
    transport = _transport()
    for authorization in schemes:
        status, body, _headers = transport(url, _request_headers(authorization))
        decision = _terms_decision(status, body)
        if decision is None:
            raise TermsRequiredError()
        if decision:
            headers = _request_headers(authorization)
            with _state_lock:
                _auth_headers[key] = dict(headers)
            return headers
        if status in (401, 403):
            denials.append(status)
        else:
            other.append(status)

    if denials and not other:
        raise HttpAuthError(denials[-1])
    code = other[-1] if other else 0
    raise ApiError(f"API_AUTH_FAILED: HTTP {code}")


def _url(path: str, query: dict[str, Any] | None = None) -> str:
    base = f"{api_root()}/{path.lstrip('/')}"
    if not query:
        return base
    pairs = [(key, str(value)) for key, value in query.items() if value is not None and str(value) != ""]
    if not pairs:
        return base
    return f"{base}?{urlencode(pairs)}"


def authorized_get(
    path: str,
    query: dict[str, Any] | None,
    username: str,
    token: str,
) -> tuple[int, str]:
    """GET one API path. Raises ``HttpAuthError`` or ``TermsRequiredError``."""
    headers = _ensure_auth(username, token)
    status, body, _response_headers = _transport()(_url(path, query), headers)
    if status in (401, 403):
        raise HttpAuthError(status)
    if status == 428:
        raise TermsRequiredError()
    return status, body


def get_json(
    path: str,
    query: dict[str, Any] | None,
    username: str,
    token: str,
) -> dict[str, Any]:
    """Return a JSON object. HTTP 404 raises ``PackageNotFound``."""
    status, body = authorized_get(path, query, username, token)
    if status == 404:
        raise PackageNotFound(f"HTTP 404 {path}")
    if status != 200:
        raise ApiError(f"HTTP {status} {path}")
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ApiError(f"API_FETCH_FAILED: invalid JSON {path}") from exc
    if not isinstance(data, dict):
        raise ApiError(f"API_FETCH_FAILED: expected object {path}")
    return data


def list_paged(
    path: str,
    query: dict[str, Any] | None,
    username: str,
    token: str,
) -> list[dict[str, Any]]:
    """Follow ``limit``/``offset`` until ``meta.count`` is consumed or a short page ends."""
    items: list[dict[str, Any]] = []
    offset = 0
    base = dict(query or {})
    for _page in range(_MAX_PAGES):
        page_query = {**base, "limit": _PAGE_LIMIT, "offset": offset}
        payload = get_json(path, page_query, username, token)
        data = payload.get("data")
        if not isinstance(data, list) or not data:
            break
        items.extend(item for item in data if isinstance(item, dict))
        offset += len(data)
        meta = payload.get("meta")
        count = meta.get("count") if isinstance(meta, dict) else None
        if isinstance(count, int) and offset >= count:
            break
        if len(data) < _PAGE_LIMIT:
            break
    else:
        raise ApiError(f"API_FETCH_FAILED: pagination did not end {path}")
    return items


def _norm_url(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return unquote(value.strip()).rstrip("/")


def matching_repositories(repos: list[dict[str, Any]], catalog: str) -> list[dict[str, Any]]:
    """Repositories whose distribution URL is this catalog's pulp base."""
    want = _norm_url(java_catalog_base(catalog))
    matches: list[dict[str, Any]] = []
    for repo in repos:
        for field in ("published_distribution_url", "url"):
            if _norm_url(repo.get(field)) == want:
                matches.append(repo)
                break
    return matches


def select_catalog_repository(repos: list[dict[str, Any]], catalog: str) -> dict[str, Any]:
    """Return the one repository for ``catalog``. Zero or several is an error."""
    matches = matching_repositories(repos, catalog)
    if len(matches) != 1:
        raise ApiError(f"{len(matches)} maven repositories match {catalog}")
    return matches[0]


def catalog_repository(catalog: str, username: str, token: str) -> dict[str, Any]:
    """Resolve ``remediated`` or ``validated`` to one Lightwell repository. Memoized."""
    key = (api_root(), catalog, username, token)
    with _state_lock:
        cached = _repositories.get(key)
    if cached is not None:
        return cached

    filtered = list_paged("/repositories", {"content_type": "maven"}, username, token)
    matches = matching_repositories(filtered, catalog)
    if len(matches) > 1:
        raise ApiError(f"{len(matches)} maven repositories match {catalog}")
    if len(matches) == 1:
        selected = matches[0]
    else:
        everything = list_paged("/repositories", None, username, token)
        selected = select_catalog_repository(everything, catalog)
    with _state_lock:
        _repositories[key] = selected
    return selected


def _java_package_path(uuid: str, group: str, name: str) -> str:
    # Group id stays dotted (org.json). quote leaves unreserved dots in place
    # and encodes reserved characters.
    return "/".join(
        [
            "repositories",
            quote(uuid, safe=""),
            "java_packages",
            quote(group, safe=""),
            quote(name, safe=""),
        ]
    )


def flatten_published_versions(payload: dict[str, Any]) -> list[str]:
    """Published Maven versions from ``version`` and ``builds[].version``.

    ``upstream_version`` is not added on its own. It is kept only when it is
    already one of those published strings.
    """
    published: list[str] = []
    seen: set[str] = set()

    def add(value: object) -> None:
        if not isinstance(value, str):
            return
        text = value.strip()
        if not text or text in seen:
            return
        seen.add(text)
        published.append(text)

    versions = payload.get("versions")
    if not isinstance(versions, list):
        return []
    for item in versions:
        if not isinstance(item, dict):
            continue
        add(item.get("version"))
        builds = item.get("builds")
        if not isinstance(builds, list):
            continue
        for build in builds:
            if isinstance(build, dict):
                add(build.get("version"))
    return published


def render_metadata_xml(versions: list[str]) -> str:
    """Minimal maven-metadata.xml. ``<latest>`` and ``<release>`` use Maven order."""
    if not versions:
        return ""
    latest = highest_version(versions)
    release = release_version(versions)
    rows = "\n".join(f"      <version>{escape(version)}</version>" for version in versions)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<metadata>\n"
        "  <versioning>\n"
        f"    <latest>{escape(latest)}</latest>\n"
        f"    <release>{escape(release)}</release>\n"
        "    <versions>\n"
        f"{rows}\n"
        "    </versions>\n"
        "  </versioning>\n"
        "</metadata>\n"
    )


def java_package_metadata_xml(
    catalog: str,
    group_id: str,
    artifact_id: str,
    username: str,
    token: str,
) -> str:
    """Synthetic maven-metadata for one Java package. Empty when it has no versions."""
    repo = catalog_repository(catalog, username, token)
    uuid = repo.get("uuid")
    if not isinstance(uuid, str) or not uuid:
        raise ApiError(f"repository for {catalog} has no uuid")
    payload = get_json(_java_package_path(uuid, group_id, artifact_id), None, username, token)
    return render_metadata_xml(flatten_published_versions(payload))


def list_advisories(
    group_id: str,
    artifact_id: str,
    username: str,
    token: str,
) -> list[dict[str, Any]]:
    """Paged remediated advisories for ``group:artifact``. HTTP 404 is an empty list.

    Filters are ``package_name`` and the remediated repository name only.
    ``package_version``, ``cve_id``, and ``latest_release`` are not sent.
    """
    repo = catalog_repository("remediated", username, token)
    query: dict[str, Any] = {"package_name": f"{group_id}:{artifact_id}"}
    name = repo.get("name")
    if isinstance(name, str) and name:
        query["repository"] = name
    try:
        return list_paged("/advisories", query, username, token)
    except PackageNotFound:
        return []
