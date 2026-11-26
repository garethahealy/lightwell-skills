"""Lightwell API v0.1 client for catalog version lists and advisories.

API auth exchanges ``LIGHTWELL_CLIENT_ID`` / ``LIGHTWELL_CLIENT_SECRET`` at the
Red Hat SSO token endpoint (``grant_type=client_credentials``,
``scope=api.console``) and sends ``Authorization: Bearer`` with the returned
``access_token``. ``GET /terms/required`` still runs once per token.

``LIGHTWELL_USERNAME`` / ``LIGHTWELL_TOKEN`` are repository credentials for
packages.redhat.com. This client does not send them.

Jar bytes, provenance bundles, and CycloneDX SBOMs stay on packages.redhat.com.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from collections.abc import Callable
from html import escape
from typing import Any
from urllib.parse import quote, unquote, urlencode

from lightwell_shared.download_http import HttpAuthError
from lightwell_shared.http_pool import HttpFetchError, shared_https_pool
from lightwell_shared.lightwell_urls import api_root, java_catalog_base, sso_token_url
from lightwell_shared.maven_version import highest_version, release_version

_NO_STORE_HEADERS = {
    "Accept": "application/json",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}
_PAGE_LIMIT = 100
_MAX_PAGES = 500
_TOKEN_SKEW_S = 30
_TOKEN_DEFAULT_TTL_S = 300
_API_CREDENTIAL = "LIGHTWELL_CLIENT_ID and LIGHTWELL_CLIENT_SECRET"

Transport = Callable[[str, dict[str, str]], tuple[int, str, dict[str, str]]]

_state_lock = threading.Lock()
_auth_headers: dict[tuple[str, str], dict[str, str]] = {}
_access_tokens: dict[tuple[str, str, str], tuple[str, float]] = {}
_repositories: dict[tuple[str, str], dict[str, Any]] = {}
_transport_override: Transport | None = None
_fixed_access_token: str | None = None
_noted_secrets: list[str] = []


class ApiError(Exception):
    """Lightwell API returned a response the client cannot use."""


class PackageNotFound(ApiError):
    """Catalog object was HTTP 404."""


class TermsRequiredError(RuntimeError):
    """HTTP 428 or ``terms.required`` — stop the phase. Do not treat as a miss."""

    def __init__(self) -> None:
        super().__init__("TERMS_REQUIRED: accept Lightwell terms before continuing")


def noted_secrets() -> list[str]:
    """Secrets observed this process. Pytest uses this to scrub tracebacks."""
    with _state_lock:
        return list(_noted_secrets)


def _note_secret(value: str) -> None:
    if len(value) < 24:
        return
    with _state_lock:
        if value not in _noted_secrets:
            _noted_secrets.append(value)


def clear_state() -> None:
    """Drop process caches. Tests use this between cases."""
    global _transport_override, _fixed_access_token
    with _state_lock:
        _auth_headers.clear()
        _access_tokens.clear()
        _repositories.clear()
        _transport_override = None
        _fixed_access_token = None
        _noted_secrets.clear()


def set_transport(transport: Transport | None) -> None:
    """Replace the HTTPS transport. ``None`` restores the shared pool."""
    global _transport_override
    with _state_lock:
        _transport_override = transport


def set_access_token(token: str | None) -> None:
    """Skip the SSO exchange. Tests inject the console access token."""
    global _fixed_access_token
    with _state_lock:
        _fixed_access_token = token or None


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
    """True when terms are accepted, False otherwise, None when terms block the call."""
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


def require_client_credentials() -> tuple[str, str]:
    """Return the API client id and secret. Missing values are ``AUTH_FAILED``."""
    client_id = os.environ.get("LIGHTWELL_CLIENT_ID", "").strip()
    client_secret = os.environ.get("LIGHTWELL_CLIENT_SECRET", "").strip()
    if not client_id or not client_secret:
        raise ApiError(f"AUTH_FAILED: set {_API_CREDENTIAL}")
    _note_secret(client_secret)
    return client_id, client_secret


def _token_ttl(payload: dict[str, Any]) -> float:
    raw = payload.get("expires_in")
    if isinstance(raw, int) and not isinstance(raw, bool):
        return max(0.0, float(raw - _TOKEN_SKEW_S))
    if isinstance(raw, str) and raw.isdigit():
        return max(0.0, float(int(raw) - _TOKEN_SKEW_S))
    return float(_TOKEN_DEFAULT_TTL_S)


def exchange_access_token(client_id: str, client_secret: str) -> tuple[str, float]:
    """POST the client-credentials grant. Return ``(access_token, ttl_seconds)``."""
    _note_secret(client_secret)
    form = urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "api.console",
        }
    ).encode("utf-8")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }
    try:
        status, body, _response_headers = shared_https_pool().request(
            sso_token_url(),
            headers=headers,
            method="POST",
            body=form,
        )
    except HttpFetchError as exc:
        raise ApiError(f"AUTH_FAILED: token endpoint {exc}") from exc
    if status in (401, 403):
        raise HttpAuthError(status, credential=_API_CREDENTIAL)
    if status != 200:
        raise ApiError(f"AUTH_FAILED: token endpoint HTTP {status}")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ApiError("AUTH_FAILED: token response was not JSON") from exc
    if not isinstance(payload, dict):
        raise ApiError("AUTH_FAILED: token response was not a JSON object")
    access_token = payload.get("access_token")
    if not isinstance(access_token, str) or not access_token.strip():
        raise ApiError("AUTH_FAILED: token response missing access_token")
    access_token = access_token.strip()
    _note_secret(access_token)
    return access_token, _token_ttl(payload)


def _access_token() -> str:
    with _state_lock:
        fixed = _fixed_access_token
    if fixed:
        _note_secret(fixed)
        return fixed

    client_id, client_secret = require_client_credentials()
    cache_key = (sso_token_url(), client_id, client_secret)
    now = time.monotonic()
    with _state_lock:
        cached = _access_tokens.get(cache_key)
    if cached is not None and cached[1] > now:
        return cached[0]

    access_token, ttl = exchange_access_token(client_id, client_secret)
    with _state_lock:
        _access_tokens[cache_key] = (access_token, time.monotonic() + ttl)
    return access_token


def _ensure_auth() -> dict[str, str]:
    access_token = _access_token()
    root = api_root()
    key = (root, access_token)
    with _state_lock:
        cached = _auth_headers.get(key)
    if cached is not None:
        return dict(cached)

    headers = _request_headers(f"Bearer {access_token}")
    status, body, _response_headers = _transport()(f"{root}/terms/required", headers)
    decision = _terms_decision(status, body)
    if decision is None:
        raise TermsRequiredError()
    if decision:
        with _state_lock:
            _auth_headers[key] = dict(headers)
        return headers
    if status in (401, 403):
        raise HttpAuthError(status, credential=_API_CREDENTIAL)
    raise ApiError(f"API_AUTH_FAILED: HTTP {status}")


def _url(path: str, query: dict[str, Any] | None = None) -> str:
    base = f"{api_root()}/{path.lstrip('/')}"
    if not query:
        return base
    pairs = [(key, str(value)) for key, value in query.items() if value is not None and str(value) != ""]
    if not pairs:
        return base
    return f"{base}?{urlencode(pairs)}"


def authorized_get(path: str, query: dict[str, Any] | None) -> tuple[int, str]:
    """GET one API path. Raises ``HttpAuthError`` or ``TermsRequiredError``."""
    headers = _ensure_auth()
    status, body, _response_headers = _transport()(_url(path, query), headers)
    if status in (401, 403):
        raise HttpAuthError(status, credential=_API_CREDENTIAL)
    if status == 428:
        raise TermsRequiredError()
    return status, body


def get_json(path: str, query: dict[str, Any] | None) -> dict[str, Any]:
    """Return a JSON object. HTTP 404 raises ``PackageNotFound``."""
    status, body = authorized_get(path, query)
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


def list_paged(path: str, query: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Follow ``limit``/``offset`` until ``meta.count`` is consumed or a short page ends."""
    items: list[dict[str, Any]] = []
    offset = 0
    base = dict(query or {})
    for _page in range(_MAX_PAGES):
        page_query = {**base, "limit": _PAGE_LIMIT, "offset": offset}
        payload = get_json(path, page_query)
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


def catalog_repository(catalog: str) -> dict[str, Any]:
    """Resolve ``remediated`` or ``validated`` to one Lightwell repository. Memoized."""
    key = (api_root(), catalog)
    with _state_lock:
        cached = _repositories.get(key)
    if cached is not None:
        return cached

    filtered = list_paged("/repositories", {"content_type": "maven"})
    matches = matching_repositories(filtered, catalog)
    if len(matches) > 1:
        raise ApiError(f"{len(matches)} maven repositories match {catalog}")
    if len(matches) == 1:
        selected = matches[0]
    else:
        everything = list_paged("/repositories", None)
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


_RHLW_RELEASE = re.compile(r"rhlw-\d+")


def _maven_coordinate(version: object, release: object) -> str | None:
    """Maven version for one API version or build.

    A ``release`` of ``rhlw-<n>`` is the build suffix. The registry publishes
    ``{version}.rhlw-<n>`` even when ``version`` itself is only the upstream line.
    """
    if not isinstance(version, str):
        return None
    text = version.strip()
    if not text:
        return None
    if isinstance(release, str) and _RHLW_RELEASE.fullmatch(release.strip()):
        suffix = f".{release.strip()}"
        if not text.endswith(suffix):
            text = f"{text}{suffix}"
    return text


def flatten_published_versions(payload: dict[str, Any]) -> list[str]:
    """Published Maven versions from version lines and their builds.

    ``builds[].release`` of ``rhlw-<n>`` is joined onto ``builds[].version``.
    ``upstream_version`` is not added on its own. A version line equal to
    ``upstream_version`` is omitted when its builds already produced coordinates.
    """
    published: list[str] = []
    seen: set[str] = set()

    def add(value: str | None) -> None:
        if not value or value in seen:
            return
        seen.add(value)
        published.append(value)

    versions = payload.get("versions")
    if not isinstance(versions, list):
        return []
    for item in versions:
        if not isinstance(item, dict):
            continue
        builds = item.get("builds")
        emitted = False
        if isinstance(builds, list):
            for build in builds:
                if not isinstance(build, dict):
                    continue
                coordinate = _maven_coordinate(
                    build.get("version") or item.get("version"),
                    build.get("release"),
                )
                if coordinate:
                    add(coordinate)
                    emitted = True
        version = item.get("version")
        upstream = item.get("upstream_version")
        line = version.strip() if isinstance(version, str) else ""
        same_as_upstream = isinstance(upstream, str) and line == upstream.strip()
        if line and (not emitted or not same_as_upstream):
            add(line)
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


def java_package_metadata_xml(catalog: str, group_id: str, artifact_id: str) -> str:
    """Synthetic maven-metadata for one Java package. Empty when it has no versions."""
    repo = catalog_repository(catalog)
    uuid = repo.get("uuid")
    if not isinstance(uuid, str) or not uuid:
        raise ApiError(f"repository for {catalog} has no uuid")
    payload = get_json(_java_package_path(uuid, group_id, artifact_id), None)
    return render_metadata_xml(flatten_published_versions(payload))


def list_advisories(group_id: str, artifact_id: str) -> list[dict[str, Any]]:
    """Paged remediated advisories for ``group:artifact``. HTTP 404 is an empty list.

    Filters are ``package_name`` and the remediated repository name only.
    ``package_version``, ``cve_id``, and ``latest_release`` are not sent.
    """
    repo = catalog_repository("remediated")
    query: dict[str, Any] = {"package_name": f"{group_id}:{artifact_id}"}
    name = repo.get("name")
    if isinstance(name, str) and name:
        query["repository"] = name
    try:
        return list_paged("/advisories", query)
    except PackageNotFound:
        return []
