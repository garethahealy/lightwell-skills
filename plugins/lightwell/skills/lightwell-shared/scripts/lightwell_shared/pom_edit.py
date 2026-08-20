"""Shared pom.xml mutation helpers for upgrade apply phases.

Requires Python 3.14+. Preserves surrounding comments where possible.
"""

from __future__ import annotations

import re
from typing import Any

from lightwell_shared.lightwell_urls import SOURCE_URL
from lightwell_shared.pom_lib import (
    ARTIFACT_RE,
    DEP_BLOCK_RE,
    EXCLUSION_RE,
    GROUP_RE,
    PROP_RE,
    SOURCE_RE,
    TRANSITIVE_OF_RE,
    VERSION_RE,
    ga,
)

_PROP_TAG_RE = re.compile(r"(<(?P<name>[A-Za-z0-9_.-]+)>)(?P<val>[^<]*?)(</(?P=name)>)")
_XML_DECL_RE = re.compile(r"^\s*(<\?xml[^?]*\?>)\s*", re.DOTALL)
_XML_TOKEN_RE = re.compile(
    r"(<!--.*?-->)|(</?[A-Za-z_][\w:.-]*(?:\s[^>]*)?>)|([^<]+)",
    re.DOTALL,
)
_ATTR_RE = re.compile(r'([A-Za-z_][\w:.-]*)\s*=\s*("[^"]*"|\'[^\']*\')')


def source_comment(catalog: str, indent: str = "        ") -> str:
    url = SOURCE_URL.get(catalog) or SOURCE_URL["remediated"]
    return f"{indent}<!-- Source: {url} -->\n"


def transitive_of_comment(via: list[str], indent: str = "        ") -> str:
    via_s = ", ".join(via) if via else "-"
    return f"{indent}<!-- Transitive of {via_s} -->\n"


def _line_indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _indent_of_dependency(match: re.Match[str]) -> str:
    """Guess indent from <dependency> or a preceding comment; default 8 spaces."""
    full = match.group(0)
    for line in full.splitlines():
        if "<dependency>" in line:
            ind = _line_indent(line)
            if ind:
                return ind
    pre = match.group("pre") or ""
    for line in reversed(pre.splitlines()):
        if line.strip().startswith("<!--"):
            ind = _line_indent(line)
            if ind:
                return ind
    return "        "


def _normalize_comment_pre(pre: str, indent: str) -> str:
    """Rewrite leading comments at ``indent``; drop orphan whitespace."""
    if not pre or not pre.strip():
        return ""
    # Keep a separating blank line when the original had an empty line first.
    leading_blank = bool(re.match(r"^\r?\n[ \t]*\r?\n", pre))
    comments: list[str] = []
    for line in pre.splitlines():
        s = line.strip()
        if s.startswith("<!--") and s.endswith("-->"):
            comments.append(f"{indent}{s}")
    if not comments:
        return ""
    body = "\n".join(comments) + "\n"
    return ("\n" + body) if leading_blank else body


def _emit_dependency(pre: str, body: str, indent: str) -> str:
    """Rebuild a dependency element with consistent open/close tag indent."""
    pre_n = _normalize_comment_pre(pre, indent)
    inner = body.strip("\n")
    # Drop a trailing indent-only line left over from the original close tag.
    lines = inner.split("\n")
    while lines and not lines[-1].strip():
        lines.pop()
    inner = "\n".join(lines)
    return f"{pre_n}{indent}<dependency>\n{inner}\n{indent}</dependency>"


def _norm_tag(tag: str) -> str:
    t = re.sub(r"\s+", " ", tag.strip())
    return t.replace(" />", "/>")


def _tag_name(tag: str) -> str:
    t = tag.strip()
    if t.startswith("</"):
        m = re.match(r"</\s*([A-Za-z_][\w:.-]*)", t)
    else:
        m = re.match(r"<\s*([A-Za-z_][\w:.-]*)", t)
    return m.group(1) if m else ""


def _format_open_tag(tag: str, prefix: str) -> list[str]:
    """Format an opening tag; multi-attr tags get aligned continuations."""
    t = tag.strip()
    m = re.match(r"<([A-Za-z_][\w:.-]*)(\s+.*?)?>", t, re.DOTALL)
    if not m:
        return [f"{prefix}{_norm_tag(t)}"]
    name, attrs = m.group(1), m.group(2)
    if not attrs or not attrs.strip():
        return [f"{prefix}<{name}>"]
    pairs = _ATTR_RE.findall(attrs)
    if len(pairs) <= 1:
        return [f"{prefix}{_norm_tag(t)}"]
    lines = [f"{prefix}<{name} {pairs[0][0]}={pairs[0][1]}"]
    pad = " " * len(f"{prefix}<{name} ")
    for key, val in pairs[1:]:
        lines.append(f"{pad}{key}={val}")
    lines[-1] += ">"
    return lines


def pretty_print_pom(text: str, *, indent_unit: str = "    ") -> str:
    """Pretty-print a Maven pom: 4-space indent, leaf tags inline, comments kept."""
    decl = ""
    rest = text
    decl_m = _XML_DECL_RE.match(text)
    if decl_m:
        decl = decl_m.group(1) + "\n"
        rest = text[decl_m.end() :]

    tokens: list[tuple[str, str]] = []
    for tok in _XML_TOKEN_RE.finditer(rest):
        if tok.group(1) is not None:
            tokens.append(("comment", tok.group(1)))
        elif tok.group(2) is not None:
            tokens.append(("tag", tok.group(2)))
        else:
            raw = tok.group(3) or ""
            if raw.strip() == "":
                if raw.count("\n") > 1:
                    tokens.append(("blank", "1"))
            else:
                tokens.append(("text", raw.strip()))

    # Drop blank lines sandwiched between comments (artifact of edits).
    filtered: list[tuple[str, str]] = []
    for idx, token in enumerate(tokens):
        if token[0] == "blank":
            prev = filtered[-1] if filtered else None
            nxt = tokens[idx + 1] if idx + 1 < len(tokens) else None
            if prev and prev[0] == "comment" and nxt and nxt[0] == "comment":
                continue
        filtered.append(token)
    tokens = filtered

    depth = 0
    out: list[str] = []
    i = 0
    while i < len(tokens):
        kind, val = tokens[i]
        if kind == "blank":
            if out and out[-1] != "":
                out.append("")
            i += 1
            continue
        if kind == "comment":
            out.append(f"{indent_unit * depth}{val.strip()}")
            i += 1
            continue
        if kind == "text":
            out.append(f"{indent_unit * depth}{val}")
            i += 1
            continue

        tag = val.strip()
        is_close = tag.startswith("</")
        is_self = tag.endswith("/>")

        if is_close:
            depth = max(0, depth - 1)
            out.append(f"{indent_unit * depth}{_norm_tag(tag)}")
            i += 1
            continue

        # <tag>text</tag> on one line
        if (
            not is_self
            and i + 2 < len(tokens)
            and tokens[i + 1][0] == "text"
            and tokens[i + 2][0] == "tag"
            and tokens[i + 2][1].strip().startswith("</")
            and _tag_name(tokens[i + 2][1]) == _tag_name(tag)
        ):
            close = _norm_tag(tokens[i + 2][1])
            open_tag = _norm_tag(tag) if len(_ATTR_RE.findall(tag)) <= 1 else None
            if open_tag is None:
                # Multi-attr leaf is unusual; still inline with collapsed open tag.
                open_tag = _norm_tag(tag)
            out.append(f"{indent_unit * depth}{open_tag}{tokens[i + 1][1]}{close}")
            i += 3
            continue

        # <tag></tag>
        if (
            not is_self
            and i + 1 < len(tokens)
            and tokens[i + 1][0] == "tag"
            and tokens[i + 1][1].strip().startswith("</")
            and _tag_name(tokens[i + 1][1]) == _tag_name(tag)
        ):
            out.append(f"{indent_unit * depth}{_norm_tag(tag)}{_norm_tag(tokens[i + 1][1])}")
            i += 2
            continue

        out.extend(_format_open_tag(tag, indent_unit * depth))
        if not is_self:
            depth += 1
        i += 1

    body = "\n".join(out)
    if body and not body.endswith("\n"):
        body += "\n"
    return decl + body


def _ensure_source_in_pre(pre: str, catalog: str, indent: str) -> str:
    url = SOURCE_URL.get(catalog)
    if not url:
        return pre
    if SOURCE_RE.search(pre):
        return SOURCE_RE.sub(
            f"<!-- Source: {url} -->",
            pre,
            count=1,
        )
    # Insert source comment just before <dependency> (pre is comments only)
    if pre and not pre.endswith("\n"):
        pre += "\n"
    return pre + source_comment(catalog, indent)


def _set_version_in_body(body: str, new_version: str) -> str:
    if VERSION_RE.search(body):
        return VERSION_RE.sub(
            f"<version>{new_version}</version>",
            body,
            count=1,
        )
    # Insert version after artifactId
    am = ARTIFACT_RE.search(body)
    if not am:
        return body
    insert_at = am.end()
    # Preserve newline/indent after artifactId
    rest = body[insert_at:]
    indent_m = re.match(r"(\s*)", rest)
    indent = indent_m.group(1) if indent_m and "\n" in rest[:8] else "\n            "
    if not indent.startswith("\n"):
        indent = "\n            "
    return body[:insert_at] + f"{indent}<version>{new_version}</version>" + rest


def set_property_value(pom_text: str, prop_name: str, new_version: str) -> str:
    block = PROP_RE.search(pom_text)
    if not block:
        raise ValueError(f"no <properties> block to set {prop_name}")

    inner = block.group(1)
    found = False

    def repl(m: re.Match[str]) -> str:
        nonlocal found
        if m.group("name") == prop_name:
            found = True
            return f"<{m.group('name')}>{new_version}</{m.group('name')}>"
        return m.group(0)

    new_inner = _PROP_TAG_RE.sub(repl, inner)
    if not found:
        raise ValueError(f"property not found: {prop_name}")
    return pom_text[: block.start(1)] + new_inner + pom_text[block.end(1) :]


def bump_direct_dependency(
    pom_text: str,
    group_id: str,
    artifact_id: str,
    new_version: str,
    *,
    catalog: str,
    property_name: str | None = None,
) -> str:
    """Bump a non-promoted direct dependency version (or its property)."""
    key = ga(group_id, artifact_id)
    if property_name:
        pom_text = set_property_value(pom_text, property_name, new_version)

    out: list[str] = []
    last = 0
    replaced = False
    for m in DEP_BLOCK_RE.finditer(pom_text):
        out.append(pom_text[last : m.start()])
        pre = m.group("pre") or ""
        body = m.group("body") or ""
        gm = GROUP_RE.search(body)
        am = ARTIFACT_RE.search(body)
        if gm and am and ga(gm.group(1).strip(), am.group(1).strip()) == key and not TRANSITIVE_OF_RE.search(pre):
            indent = _indent_of_dependency(m)
            pre = _ensure_source_in_pre(pre, catalog, indent)
            if not property_name:
                body = _set_version_in_body(body, new_version)
            else:
                # Keep ${property} ref; still refresh Source
                pass
            out.append(_emit_dependency(pre, body, indent))
            replaced = True
        else:
            out.append(m.group(0))
        last = m.end()
    out.append(pom_text[last:])
    if not replaced:
        raise ValueError(f"direct dependency not found: {key}")
    return "".join(out)


def _exclusion_xml(group_id: str, artifact_id: str, indent: str) -> str:
    i2 = indent + "    "
    return (
        f"{indent}<exclusion>\n"
        f"{i2}<groupId>{group_id}</groupId>\n"
        f"{i2}<artifactId>{artifact_id}</artifactId>\n"
        f"{indent}</exclusion>\n"
    )


def ensure_exclusion_on_parent(
    pom_text: str,
    parent_ga: str,
    exclude_g: str,
    exclude_a: str,
) -> str:
    """Add exclusion to a direct (non-promoted) parent dependency if missing.

    Raises ValueError if the parent GA is not found in the pom.
    """
    out: list[str] = []
    last = 0
    parent_found = False
    for m in DEP_BLOCK_RE.finditer(pom_text):
        out.append(pom_text[last : m.start()])
        pre = m.group("pre") or ""
        body = m.group("body") or ""
        gm = GROUP_RE.search(body)
        am = ARTIFACT_RE.search(body)
        if gm and am and ga(gm.group(1).strip(), am.group(1).strip()) == parent_ga and not TRANSITIVE_OF_RE.search(pre):
            parent_found = True
            existing = {ga(x.group(1).strip(), x.group(2).strip()) for x in EXCLUSION_RE.finditer(body)}
            want = ga(exclude_g, exclude_a)
            dep_indent = _indent_of_dependency(m)
            if want not in existing:
                child = dep_indent + "    "
                excl = _exclusion_xml(exclude_g, exclude_a, child + "    ")
                if re.search(r"<exclusions>", body, re.IGNORECASE):
                    body = re.sub(
                        r"(<exclusions>)",
                        r"\1\n" + excl.rstrip("\n"),
                        body,
                        count=1,
                        flags=re.IGNORECASE,
                    )
                else:
                    body = body.rstrip() + f"\n{child}<exclusions>\n" + excl + f"{child}</exclusions>\n"
            out.append(_emit_dependency(pre, body, dep_indent))
        else:
            out.append(m.group(0))
        last = m.end()
    out.append(pom_text[last:])
    if parent_ga and not parent_found:
        raise ValueError(f"parent dependency not found: {parent_ga}")
    return "".join(out)


def remove_exclusion_from_parent(
    pom_text: str,
    parent_ga: str,
    exclude_g: str,
    exclude_a: str,
) -> str:
    want = ga(exclude_g, exclude_a)
    out: list[str] = []
    last = 0
    for m in DEP_BLOCK_RE.finditer(pom_text):
        out.append(pom_text[last : m.start()])
        pre = m.group("pre") or ""
        body = m.group("body") or ""
        gm = GROUP_RE.search(body)
        am = ARTIFACT_RE.search(body)
        if gm and am and ga(gm.group(1).strip(), am.group(1).strip()) == parent_ga and not TRANSITIVE_OF_RE.search(pre):

            def drop_excl(em: re.Match[str]) -> str:
                if ga(em.group(1).strip(), em.group(2).strip()) == want:
                    return ""
                return em.group(0)

            body = EXCLUSION_RE.sub(drop_excl, body)
            # Drop empty exclusions block
            body = re.sub(
                r"<exclusions>\s*</exclusions>\s*",
                "",
                body,
                flags=re.IGNORECASE,
            )
            out.append(_emit_dependency(pre, body, _indent_of_dependency(m)))
        else:
            out.append(m.group(0))
        last = m.end()
    out.append(pom_text[last:])
    return "".join(out)


def remove_promoted_dependency(pom_text: str, group_id: str, artifact_id: str) -> str:
    key = ga(group_id, artifact_id)
    out: list[str] = []
    last = 0
    removed = False
    for m in DEP_BLOCK_RE.finditer(pom_text):
        out.append(pom_text[last : m.start()])
        pre = m.group("pre") or ""
        body = m.group("body") or ""
        gm = GROUP_RE.search(body)
        am = ARTIFACT_RE.search(body)
        if gm and am and ga(gm.group(1).strip(), am.group(1).strip()) == key and TRANSITIVE_OF_RE.search(pre):
            # Drop preceding blank line noise carefully: keep one newline
            removed = True
        else:
            out.append(m.group(0))
        last = m.end()
    out.append(pom_text[last:])
    if not removed:
        raise ValueError(f"promoted dependency not found: {key}")
    text = "".join(out)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text


def upsert_promoted_dependency(
    pom_text: str,
    group_id: str,
    artifact_id: str,
    version: str,
    via: list[str],
) -> str:
    """Update existing promoted dep or append a new one before </dependencies>."""
    key = ga(group_id, artifact_id)
    out: list[str] = []
    last = 0
    found = False
    for m in DEP_BLOCK_RE.finditer(pom_text):
        out.append(pom_text[last : m.start()])
        pre = m.group("pre") or ""
        body = m.group("body") or ""
        gm = GROUP_RE.search(body)
        am = ARTIFACT_RE.search(body)
        if gm and am and ga(gm.group(1).strip(), am.group(1).strip()) == key and TRANSITIVE_OF_RE.search(pre):
            indent = _indent_of_dependency(m)
            # Rebuild pre comments
            # Keep non-transitive/non-source comments
            kept = []
            for line in pre.splitlines(keepends=True):
                if TRANSITIVE_OF_RE.search(line) or SOURCE_RE.search(line):
                    continue
                kept.append(line)
            pre = "".join(kept)
            if pre and not pre.endswith("\n"):
                pre += "\n"
            pre += transitive_of_comment(via, indent)
            pre += source_comment("remediated", indent)
            body = _set_version_in_body(body, version)
            out.append(_emit_dependency(pre, body, indent))
            found = True
        else:
            out.append(m.group(0))
        last = m.end()
    out.append(pom_text[last:])
    text = "".join(out)
    if found:
        return text

    # Append before </dependencies>, preserving the closing tag's indent.
    indent = "        "
    block = (
        f"\n{transitive_of_comment(via, indent)}"
        f"{source_comment('remediated', indent)}"
        f"{indent}<dependency>\n"
        f"{indent}    <groupId>{group_id}</groupId>\n"
        f"{indent}    <artifactId>{artifact_id}</artifactId>\n"
        f"{indent}    <version>{version}</version>\n"
        f"{indent}</dependency>\n"
    )
    close_m = re.search(r"(?P<ws>[ \t]*)</dependencies>", text)
    if close_m:
        ws = close_m.group("ws")
        return text[: close_m.start()] + block + f"{ws}</dependencies>" + text[close_m.end() :]
    raise ValueError("no </dependencies> in pom")


def apply_direct_collect_row(pom_text: str, row: dict[str, Any]) -> str:
    return bump_direct_dependency(
        pom_text,
        row["groupId"],
        row["artifactId"],
        row["to"],
        catalog=row.get("catalog") or "unknown",
        property_name=row.get("property"),
    )


def apply_transitive_collect_row(pom_text: str, row: dict[str, Any]) -> str:
    action = row["action"]
    g, a = row["groupId"], row["artifactId"]
    via = list(row.get("via") or [])
    if action == "DROP":
        for parent in via:
            if parent and parent != "-":
                pom_text = remove_exclusion_from_parent(pom_text, parent, g, a)
        return remove_promoted_dependency(pom_text, g, a)
    if action in {"PROMOTE", "UPDATE", "KEEP"}:
        to_ver = row.get("to") or row.get("from")
        if not to_ver:
            raise ValueError(f"missing version for {row.get('ga')}")
        for parent in via:
            if parent and parent != "-":
                pom_text = ensure_exclusion_on_parent(pom_text, parent, g, a)
        return upsert_promoted_dependency(pom_text, g, a, to_ver, via)
    raise ValueError(f"unknown action: {action}")
