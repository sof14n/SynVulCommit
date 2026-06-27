from __future__ import annotations

import re
from typing import Iterable, Match


DEFAULT_WINDOW_SIZE = 200
DEFAULT_STRIDE = 5
TOKEN_RE = re.compile(r"[A-Za-z_]\w*|\d+(?:\.\d+)?|==|!=|<=|>=|//|<<|>>|\*\*|[^\s]")


def token_matches(source: str) -> list[Match[str]]:
    return list(TOKEN_RE.finditer(source))


def code_token_count(source: str) -> int:
    return len(token_matches(source))


def badpart_spans(source: str, badparts: Iterable[str]) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for part in badparts:
        if not part:
            continue
        position = source.find(part)
        while position >= 0:
            spans.append((position, position + len(part)))
            position = source.find(part, position + max(1, len(part)))
    return spans


def window_start_indexes(token_count: int, window_size: int = DEFAULT_WINDOW_SIZE, stride: int = DEFAULT_STRIDE) -> list[int]:
    if token_count <= 0:
        return []
    starts = list(range(0, max(1, token_count - window_size + 1), stride))
    last_start = max(0, token_count - window_size)
    if last_start not in starts:
        starts.append(last_start)
    return starts


def window_labels(
    source: str,
    badparts: Iterable[str],
    window_size: int = DEFAULT_WINDOW_SIZE,
    stride: int = DEFAULT_STRIDE,
) -> list[int]:
    matches = token_matches(source)
    spans = badpart_spans(source, badparts)
    labels: list[int] = []
    for start in window_start_indexes(len(matches), window_size, stride):
        tokens = matches[start : start + window_size]
        if not tokens:
            continue
        first, last = tokens[0].start(), tokens[-1].end()
        labels.append(int(any(first < end and start_pos < last for start_pos, end in spans)))
    return labels


def analyze_window_balance(
    vulnerable_code: str,
    badparts: Iterable[str],
    fixed_code: str,
    window_size: int = DEFAULT_WINDOW_SIZE,
    stride: int = DEFAULT_STRIDE,
) -> dict[str, int | float]:
    matches = token_matches(vulnerable_code)
    fixed_token_count = code_token_count(fixed_code)
    spans = badpart_spans(vulnerable_code, badparts)
    labels = window_labels(vulnerable_code, badparts, window_size, stride)
    badpart_token_count = sum(
        1
        for match in matches
        if any(match.start() < end and start_pos < match.end() for start_pos, end in spans)
    )
    vulnerable_token_count = len(matches)
    ratio = round(badpart_token_count / vulnerable_token_count, 6) if vulnerable_token_count else 0.0
    return {
        "window_size": window_size,
        "stride": stride,
        "vulnerable_token_count": vulnerable_token_count,
        "fixed_token_count": fixed_token_count,
        "positive_window_count": sum(labels),
        "negative_window_count": len(labels) - sum(labels),
        "badpart_token_count": badpart_token_count,
        "badpart_token_ratio": ratio,
    }
