"""Shared pom.xml / dependency:tree parsing for Lightwell skill helpers.

Requires Python 3.14+.
"""

from __future__ import annotations

import re
from typing import Any

DEP_BLOCK_RE = re.compile(
    r"(?P<pre>(?:\s*<!--.*?-->\s*)*)"
    r"<dependency>(?P<body>.*?)</dependency>",
    re.DOTALL,
)
TRANSITIVE_OF_RE = re.compile(
    r"<!--\s*Transitive of\s+(.+?)\s*-->",
    re.IGNORECASE,
)
SOURCE_RE = re.compile(
    r"<!--\s*Source:\s*(https?://[^\s>]+)\s*-->",
    re.IGNORECASE,
)
GROUP_RE = re.compile(r"<groupId>\s*([^<]+?)\s*</groupId>")
ARTIFACT_RE = re.compile(r"<artifactId>\s*([^<]+?)\s*</artifactId>")
VERSION_RE = re.compile(r"<version>\s*([^<]+?)\s*</version>")
SCOPE_RE = re.compile(r"<scope>\s*([^<]+?)\s*</scope>")
EXCLUSION_RE = re.compile(
    r"<exclusion>\s*<groupId>\s*([^<]+?)\s*</groupId>\s*"
    r"<artifactId>\s*([^<]+?)\s*</artifactId>\s*</exclusion>",
    re.DOTALL,
)
PROP_RE = re.compile(
    r"<properties>(.*?)</properties>",
    re.DOTALL | re.IGNORECASE,
)
PROP_ENTRY_RE = re.compile(r"<([A-Za-z0-9_.-]+)>\s*([^<]+?)\s*</\1>")
PROP_REF_RE = re.compile(r"^\$\{([A-Za-z0-9_.-]+)\}$")
# packaging may be jar/war/bundle/…; optional Maven "(omitted for …)" suffix
TREE_NODE_RE = re.compile(
    r"^((?:\|  )|(?:   ))*"
    r"(?:\+-|\\-)\s+"
    r"([^:]+):([^:]+):[^:]+:([^:]+):(\w+)"
    r"(?:\s+\(.*\))?\s*$"
)
RHLW_RE = re.compile(r"^(?P<base>.+)\.rhlw-(?P<n>\d+)$")
SKIP_SCOPES = frozenset({"test", "provided", "system", "import"})


def ga(group: str, artifact: str) -> str:
    return f"{group}:{artifact}"


def parse_via_list(text: str) -> list[str]:
    parts = [p.strip() for p in text.split(",")]
    out: list[str] = []
    for p in parts:
        if not p or p.count(":") != 1:
            continue
        out.append(p)
    return out


def parse_properties(pom_text: str) -> dict[str, str]:
    props: dict[str, str] = {}
    block = PROP_RE.search(pom_text)
    if not block:
        return props
    for m in PROP_ENTRY_RE.finditer(block.group(1)):
        props[m.group(1)] = m.group(2).strip()
    return props


def resolve_version(raw: str, props: dict[str, str]) -> tuple[str, str | None]:
    """Return (resolved_version, property_name|None)."""
    if not raw:
        return "", None
    m = PROP_REF_RE.match(raw.strip())
    if not m:
        return raw.strip(), None
    name = m.group(1)
    return props.get(name, raw.strip()), name


def infer_catalog_from_source(url: str | None) -> str | None:
    if not url:
        return None
    if "/java/remediated/" in url or "/java-remediated/" in url:
        return "remediated"
    if "/java/validated/" in url or "/java-validated/" in url:
        return "validated"
    return None


def infer_catalog(version: str, source_url: str | None) -> str:
    from_source = infer_catalog_from_source(source_url)
    if from_source:
        return from_source
    if RHLW_RE.match(version):
        return "remediated"
    return "unknown"


def parse_pom(pom_text: str) -> dict[str, Any]:
    props = parse_properties(pom_text)
    directs: list[dict[str, Any]] = []
    promoted: list[dict[str, Any]] = []
    exclusions: dict[str, list[str]] = {}
    directs_map: dict[str, str] = {}

    for m in DEP_BLOCK_RE.finditer(pom_text):
        pre = m.group("pre") or ""
        body = m.group("body") or ""
        gm = GROUP_RE.search(body)
        am = ARTIFACT_RE.search(body)
        vm = VERSION_RE.search(body)
        if not gm or not am:
            continue
        g, a = gm.group(1).strip(), am.group(1).strip()
        key = ga(g, a)
        raw_version = vm.group(1).strip() if vm else ""
        version, prop_name = resolve_version(raw_version, props)
        sm = SCOPE_RE.search(body)
        scope = sm.group(1).strip().lower() if sm else "compile"
        if scope in SKIP_SCOPES:
            continue

        ex_list = [ga(x.group(1).strip(), x.group(2).strip()) for x in EXCLUSION_RE.finditer(body)]
        if ex_list:
            exclusions[key] = sorted(set(ex_list))

        source_m = SOURCE_RE.search(pre)
        source_url = source_m.group(1).strip() if source_m else None
        catalog = infer_catalog(version, source_url)

        tm = TRANSITIVE_OF_RE.search(pre)
        if tm:
            via = parse_via_list(tm.group(1))
            promoted.append(
                {
                    "groupId": g,
                    "artifactId": a,
                    "ga": key,
                    "version": version,
                    "rawVersion": raw_version,
                    "property": prop_name,
                    "catalog": "remediated",
                    "source": source_url,
                    "via": via,
                    "alreadyPromoted": True,
                }
            )
        else:
            directs_map[key] = version
            directs.append(
                {
                    "groupId": g,
                    "artifactId": a,
                    "ga": key,
                    "version": version,
                    "rawVersion": raw_version,
                    "property": prop_name,
                    "catalog": catalog,
                    "source": source_url,
                }
            )

    return {
        "properties": props,
        "directs": directs,
        "directsMap": directs_map,
        "promoted": promoted,
        "exclusions": exclusions,
    }


def parse_tree(tree_text: str) -> list[dict[str, Any]]:
    """Return nodes with ga, version, scope, depth, via_direct."""
    nodes: list[dict[str, Any]] = []
    stack: list[tuple[int, str]] = []

    for raw in tree_text.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("[INFO]") or line.startswith("[WARNING]"):
            continue
        if re.match(r"^[\w.-]+:[\w.-]+:", line) and not line.lstrip().startswith(("+", "\\", "|")):
            continue

        m = TREE_NODE_RE.match(line)
        if not m:
            continue
        prefix, group, artifact, version, scope = m.groups()
        depth = (len(prefix) // 3) + 1 if prefix is not None else 1

        key = ga(group.strip(), artifact.strip())
        scope_l = scope.lower()
        while stack and stack[-1][0] >= depth:
            stack.pop()
        via_direct = ""
        if depth == 1:
            via_direct = key
        else:
            for d, gakey in stack:
                if d == 1:
                    via_direct = gakey
                    break

        stack.append((depth, key))
        nodes.append(
            {
                "ga": key,
                "version": version.strip(),
                "scope": scope_l,
                "depth": depth,
                "via_direct": via_direct,
            }
        )
    return nodes


def versions_by_ga(tree_text: str) -> dict[str, str]:
    """Map ga -> version for non-skipped scopes (first occurrence wins)."""
    out: dict[str, str] = {}
    for n in parse_tree(tree_text):
        if n["scope"] in SKIP_SCOPES:
            continue
        out.setdefault(n["ga"], n["version"])
    return out


def indexes_by_via_direct(tree_text: str) -> dict[str, dict[str, str]]:
    """Map via_direct parent ga -> {ga: version} for non-skipped scopes."""
    out: dict[str, dict[str, str]] = {}
    for n in parse_tree(tree_text):
        if n["scope"] in SKIP_SCOPES:
            continue
        via = n.get("via_direct") or ""
        if not via:
            continue
        bucket = out.setdefault(via, {})
        bucket.setdefault(n["ga"], n["version"])
    return out


def _upstream_parts(version: str) -> tuple[str, int]:
    """Return (base_without_rhlw, rhlw_n_or_-1)."""
    match = RHLW_RE.match(version)
    if match:
        return match.group("base"), int(match.group("n"))
    return version, -1


def rhlw_build(version: str) -> int:
    """Lightwell build number, or -1 when version has no `.rhlw-*` suffix."""
    return _upstream_parts(version)[1]


def semver_triple(version: str) -> tuple[int, int, int] | None:
    """Parse SemVer (major, minor, patch) from the upstream base.

    Strips `.rhlw-*`. Takes the first three numeric segments; pads missing
    minor/patch with 0 (`20220320` → `(20220320, 0, 0)`). Returns None when
    the version does not start with a numeric SemVer component.
    """
    base, _ = _upstream_parts(version)
    nums: list[int] = []
    for chunk in re.split(r"[.\-_]", base):
        if chunk.isdigit():
            nums.append(int(chunk))
            if len(nums) == 3:
                break
        elif nums:
            break
        else:
            return None
    if not nums:
        return None
    while len(nums) < 3:
        nums.append(0)
    return (nums[0], nums[1], nums[2])


def version_key(version: str) -> tuple:
    """Best-effort sortable key; empty tuple if unparsable."""
    base, rhlw_n = _upstream_parts(version)
    parts: list[object] = []
    for chunk in re.split(r"[.\-_]", base):
        if chunk.isdigit():
            parts.append(int(chunk))
        elif chunk:
            parts.append(chunk)
    parts.append(rhlw_n)
    return tuple(parts)


def is_newer(candidate: str, current: str) -> bool:
    """True if candidate is a strict upgrade (never a SemVer downgrade).

    Prefers SemVer major.minor.patch; same triple uses higher `.rhlw-*` as
    newer. Incomparable / unparsable pairs are not newer (caller should ASK).
    """
    if candidate == current:
        return False
    c = semver_triple(candidate)
    u = semver_triple(current)
    if c is not None and u is not None:
        if c > u:
            return True
        if c < u:
            return False
        return rhlw_build(candidate) > rhlw_build(current)
    try:
        return version_key(candidate) > version_key(current)
    except TypeError:
        return False


def ask_reason(from_ver: str, to_ver: str) -> str:
    """Machine-readable reason for an ASK SemVer gate."""
    f = semver_triple(from_ver)
    t = semver_triple(to_ver)
    if f is None or t is None:
        return "semver-unsure"
    if f[0] != t[0]:
        return "semver-major"
    if f[1] != t[1]:
        return "semver-minor"
    if f[2] == t[2]:
        return "semver-patch-same"
    return "semver-ask"


def needs_ask(_group_id: str, from_ver: str, to_ver: str) -> bool:
    """True when applying to_ver needs user approval.

    SemVer policy for Lightwell moves:
    - never auto-apply major or minor bumps
    - ASK when SemVer cannot be parsed (unsure)
    - auto-OK when major+minor+patch match (same-base `.rhlw-*` / higher build)
    - auto-OK when major+minor match and patch increases
    """
    f = semver_triple(from_ver)
    t = semver_triple(to_ver)
    if f is None or t is None:
        return True
    if f[0] != t[0] or f[1] != t[1]:
        return True
    return False
