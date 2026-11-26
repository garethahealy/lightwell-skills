"""Maven version order for synthetic ``<latest>`` / ``<release>`` tags.

Port of ``org.apache.maven.artifact.versioning.ComparableVersion`` so the
version chosen from a Lightwell API list matches pulp ``maven-metadata.xml``.
Trailing zeros are null. Qualifiers follow Maven:
alpha < beta < milestone < rc < snapshot < release < sp.
Unknown qualifiers (including ``rhlw``) sort after release.
"""

from __future__ import annotations

import re
from functools import cmp_to_key

_QUALIFIERS = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"]
_RELEASE_KEY = str(_QUALIFIERS.index(""))
_ALIASES = {"ga": "", "final": "", "release": "", "cr": "rc"}
_DIGIT_ALIASES = {"a": "alpha", "b": "beta", "m": "milestone"}
_SNAPSHOT_SPLIT = re.compile(r"[.\-]")


class _Item:
    def is_null(self) -> bool:
        return False

    def compare(self, other: _Item | None) -> int:
        raise NotImplementedError


def _cmp_int(left: int, right: int) -> int:
    return (left > right) - (left < right)


def _cmp_str(left: str, right: str) -> int:
    return (left > right) - (left < right)


def _qualifier_key(value: str) -> str:
    try:
        return str(_QUALIFIERS.index(value))
    except ValueError:
        return f"{len(_QUALIFIERS)}-{value}"


class _Int(_Item):
    def __init__(self, value: int) -> None:
        self.value = value

    def is_null(self) -> bool:
        return self.value == 0

    def compare(self, other: _Item | None) -> int:
        if other is None:
            return _cmp_int(self.value, 0)
        if isinstance(other, _Int):
            return _cmp_int(self.value, other.value)
        # 1.1 > 1-sp and 1.1 > 1-1
        return 1


class _String(_Item):
    def __init__(self, value: str, *, followed_by_digit: bool) -> None:
        if followed_by_digit and len(value) == 1:
            value = _DIGIT_ALIASES.get(value, value)
        self.value = _ALIASES.get(value, value)

    def is_null(self) -> bool:
        return _qualifier_key(self.value) == _RELEASE_KEY

    def compare(self, other: _Item | None) -> int:
        if other is None or isinstance(other, _String):
            right = _RELEASE_KEY if other is None else _qualifier_key(other.value)
            return _cmp_str(_qualifier_key(self.value), right)
        # 1-sp < 1.1 and 1.any < 1-1
        return -1


class _List(_Item):
    def __init__(self) -> None:
        self.items: list[_Item] = []

    def add(self, item: _Item) -> None:
        self.items.append(item)

    def is_null(self) -> bool:
        return not self.items

    def normalize(self) -> None:
        index = len(self.items) - 1
        while index >= 0:
            last = self.items[index]
            if last.is_null():
                del self.items[index]
            elif not isinstance(last, _List):
                break
            index -= 1

    def compare(self, other: _Item | None) -> int:
        if other is None:
            if not self.items:
                return 0
            return self.items[0].compare(None)
        if isinstance(other, _Int):
            return -1
        if isinstance(other, _String):
            return 1
        if not isinstance(other, _List):
            return 1
        width = max(len(self.items), len(other.items))
        for index in range(width):
            left = self.items[index] if index < len(self.items) else None
            right = other.items[index] if index < len(other.items) else None
            if left is None:
                result = 0 if right is None else -right.compare(None)
            else:
                result = left.compare(right)
            if result != 0:
                return result
        return 0


def _int_item(buf: str) -> _Int:
    stripped = buf.lstrip("0")
    if not stripped:
        return _Int(0)
    return _Int(int(stripped))


def _parse_item(is_digit: bool, buf: str) -> _Item:
    if is_digit:
        return _int_item(buf)
    return _String(buf, followed_by_digit=False)


def _parse(version: str) -> _List:
    root = _List()
    stack: list[_List] = [root]
    current = root
    is_digit = False
    start = 0
    text = version.lower()

    for index, char in enumerate(text):
        if char == ".":
            if index == start:
                current.add(_Int(0))
            else:
                current.add(_parse_item(is_digit, text[start:index]))
            start = index + 1
        elif char == "-":
            if index == start:
                current.add(_Int(0))
            else:
                current.add(_parse_item(is_digit, text[start:index]))
            start = index + 1
            child = _List()
            current.add(child)
            current = child
            stack.append(child)
        elif char.isdigit():
            if not is_digit and index > start:
                current.add(_String(text[start:index], followed_by_digit=True))
                start = index
                child = _List()
                current.add(child)
                current = child
                stack.append(child)
            is_digit = True
        else:
            if is_digit and index > start:
                current.add(_parse_item(True, text[start:index]))
                start = index
                child = _List()
                current.add(child)
                current = child
                stack.append(child)
            is_digit = False

    if len(text) > start:
        current.add(_parse_item(is_digit, text[start:]))

    while stack:
        stack.pop().normalize()
    return root


def compare_versions(left: str, right: str) -> int:
    """Return negative, zero, or positive like Maven ``ComparableVersion``."""
    return _parse(left).compare(_parse(right))


def highest_version(versions: list[str]) -> str:
    """Return the greatest version under Maven version order."""
    return max(versions, key=cmp_to_key(compare_versions))


def is_snapshot(version: str) -> bool:
    return "snapshot" in _SNAPSHOT_SPLIT.split(version.lower())


def release_version(versions: list[str]) -> str:
    """Greatest non-snapshot version, or the greatest version when all are snapshots."""
    releases = [version for version in versions if not is_snapshot(version)]
    return highest_version(releases or list(versions))
