from __future__ import annotations

import difflib


def make_unified_diff(before: str, after: str, filename: str) -> str:
    before_lines = before.splitlines()
    after_lines = after.splitlines()
    lines = list(
        difflib.unified_diff(
            before_lines,
            after_lines,
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
            lineterm="",
        )
    )
    return "\n".join(lines) + "\n"


def extract_changed_parts(diff_text: str) -> tuple[list[str], list[str]]:
    badparts: list[str] = []
    goodparts: list[str] = []
    for line in diff_text.splitlines():
        if not line:
            continue
        if line.startswith(("---", "+++", "@@")):
            continue
        if line.startswith("-"):
            value = line[1:].strip()
            if value:
                badparts.append(value)
        elif line.startswith("+"):
            value = line[1:].strip()
            if value:
                goodparts.append(value)
    return _unique(badparts), _unique(goodparts)


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            result.append(value)
            seen.add(value)
    return result
