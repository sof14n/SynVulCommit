from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass

from .vudenc_loader import VudencFileRecord


@dataclass(frozen=True)
class CodeExample:
    mode: str
    text: str
    label: int
    group_id: str
    origin: str


def build_examples(
    records: list[VudencFileRecord],
    *,
    context_chars: int = 600,
    negative_ratio: int = 2,
    seed: int = 1337,
) -> list[CodeExample]:
    examples: list[CodeExample] = []
    for record in records:
        vulnerable_spans = _find_vulnerable_spans(record.source, record.badparts)
        if not vulnerable_spans:
            continue
        positives = [
            CodeExample(
                mode=record.mode,
                text=_window(record.source, start, end, context_chars),
                label=1,
                group_id=record.group_id,
                origin=record.origin,
            )
            for start, end in vulnerable_spans
        ]
        negatives = _negative_examples(
            record=record,
            vulnerable_spans=vulnerable_spans,
            target_count=max(1, len(positives) * negative_ratio),
            context_chars=context_chars,
            seed=seed,
        )
        examples.extend(positives)
        examples.extend(negatives)
    return _dedupe_examples(examples)


def split_real_examples(
    examples: list[CodeExample],
    *,
    train_fraction: float = 0.70,
    validation_fraction: float = 0.15,
) -> dict[str, list[CodeExample]]:
    splits = {"train": [], "validation": [], "test": []}
    for example in examples:
        bucket = _stable_bucket(example.group_id)
        if bucket < train_fraction:
            splits["train"].append(example)
        elif bucket < train_fraction + validation_fraction:
            splits["validation"].append(example)
        else:
            splits["test"].append(example)
    return splits


def _find_vulnerable_spans(source: str, badparts: tuple[str, ...]) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for badpart in badparts:
        variants = [badpart, badpart.strip(), _compact_whitespace(badpart)]
        for variant in variants:
            if not variant:
                continue
            start = source.find(variant)
            if start >= 0:
                spans.append((start, start + len(variant)))
                break
    return _merge_spans(spans)


def _negative_examples(
    *,
    record: VudencFileRecord,
    vulnerable_spans: list[tuple[int, int]],
    target_count: int,
    context_chars: int,
    seed: int,
) -> list[CodeExample]:
    source = record.source
    if not source.strip():
        return []
    rng = random.Random(f"{seed}:{record.group_id}")
    candidates: list[tuple[int, int]] = []
    stride = max(80, context_chars // 2)
    width = min(context_chars, max(80, len(source)))
    for start in range(0, max(len(source), 1), stride):
        end = min(len(source), start + width)
        if end <= start:
            continue
        if not _overlaps_any(start, end, vulnerable_spans):
            candidates.append((start, end))
    rng.shuffle(candidates)

    negatives: list[CodeExample] = []
    for start, end in candidates[:target_count]:
        text = source[start:end].strip()
        if not text:
            continue
        negatives.append(
            CodeExample(
                mode=record.mode,
                text=text,
                label=0,
                group_id=record.group_id,
                origin=record.origin,
            )
        )
    return negatives


def _window(source: str, start: int, end: int, context_chars: int) -> str:
    extra = max(0, context_chars - (end - start))
    left = max(0, start - extra // 2)
    right = min(len(source), end + extra // 2)
    return source[left:right].strip()


def _merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
            continue
        prev_start, prev_end = merged[-1]
        merged[-1] = (prev_start, max(prev_end, end))
    return merged


def _overlaps_any(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    return any(start < span_end and end > span_start for span_start, span_end in spans)


def _dedupe_examples(examples: list[CodeExample]) -> list[CodeExample]:
    seen: set[tuple[str, int, str]] = set()
    result: list[CodeExample] = []
    for example in examples:
        key = (example.mode, example.label, example.text)
        if key in seen:
            continue
        seen.add(key)
        result.append(example)
    return result


def _stable_bucket(value: str) -> float:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return int(digest[:12], 16) / float(0xFFFFFFFFFFFF)


def _compact_whitespace(value: str) -> str:
    return " ".join(value.split())

