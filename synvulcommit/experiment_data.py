"""Dataset preparation primitives for the controlled VUDENC experiments."""

from __future__ import annotations

import hashlib
import json
import random
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from .windowing import badpart_spans, token_matches, window_start_indexes


CANONICAL_MODES = (
    "sql",
    "command_injection",
    "directory_traversal",
    "open_redirect",
    "remote_code_execution",
    "xss",
    "xsrf",
)
MODE_ALIASES = {"path_disclosure": "directory_traversal"}
CONTEXT_FIELDS = ("application_type", "flow_pattern", "difficulty", "structure")


@dataclass(frozen=True)
class CommitRecord:
    dataset: str
    mode: str
    commit_id: str
    repo: str
    filename: str
    source: str
    fixed_source: str
    badparts: tuple[str, ...]
    goodparts: tuple[str, ...]
    context: dict[str, str]

    @property
    def group_id(self) -> str:
        # A VUDENC commit may change multiple files. They must never cross splits.
        return f"{self.dataset}:{self.mode}:{self.repo}:{self.commit_id}"

    def manifest(self) -> dict[str, Any]:
        result = asdict(self)
        result["badparts"] = list(self.badparts)
        result["goodparts"] = list(self.goodparts)
        result["group_id"] = self.group_id
        return result


def canonical_mode(value: str) -> str:
    normalized = value.strip().lower()
    return MODE_ALIASES.get(normalized, normalized)


def load_synthetic_records(path: Path) -> list[CommitRecord]:
    records: list[CommitRecord] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            raw = json.loads(line)
            mode = canonical_mode(str(raw.get("mode", "")))
            if mode not in CANONICAL_MODES:
                continue
            context_raw = raw.get("context") if isinstance(raw.get("context"), dict) else {}
            context = {field: str(context_raw.get(field, "unknown")) for field in CONTEXT_FIELDS}
            records.append(
                CommitRecord(
                    dataset="synthetic",
                    mode=mode,
                    commit_id=str(raw["id"]),
                    repo="synvulcommit",
                    filename=str(raw.get("filename", "sample.py")),
                    source=str(raw.get("vulnerable_code", "")),
                    fixed_source=str(raw.get("fixed_code", "")),
                    badparts=tuple(str(item) for item in raw.get("badparts", []) if str(item).strip()),
                    goodparts=tuple(str(item) for item in raw.get("goodparts", []) if str(item).strip()),
                    context=context,
                )
            )
    return records


def load_vudenc_records(root: Path) -> list[CommitRecord]:
    records: list[CommitRecord] = []
    for path in sorted(root.glob("plain_*")):
        source_mode = path.name.removeprefix("plain_")
        mode = canonical_mode(source_mode)
        if mode not in CANONICAL_MODES:
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            continue
        for repo, commits in payload.items():
            if not isinstance(commits, dict):
                continue
            for commit_id, commit in commits.items():
                files = commit.get("files", {}) if isinstance(commit, dict) else {}
                if not isinstance(files, dict):
                    continue
                for filename, file_data in files.items():
                    if not isinstance(file_data, dict):
                        continue
                    changes = file_data.get("changes", [])
                    changes = changes if isinstance(changes, list) else []
                    badparts = tuple(
                        str(part)
                        for change in changes if isinstance(change, dict)
                        for part in change.get("badparts", []) if str(part).strip()
                    )
                    goodparts = tuple(
                        str(part)
                        for change in changes if isinstance(change, dict)
                        for part in change.get("goodparts", []) if str(part).strip()
                    )
                    source = str(file_data.get("sourceWithComments") or file_data.get("source") or "")
                    records.append(
                        CommitRecord(
                            dataset="real",
                            mode=mode,
                            commit_id=str(commit_id),
                            repo=str(repo),
                            filename=str(filename),
                            source=source,
                            fixed_source=str(file_data.get("sourcecodeafter", "")),
                            badparts=badparts,
                            goodparts=goodparts,
                            context={field: "legacy_unknown" for field in CONTEXT_FIELDS},
                        )
                    )
    return records


def _stable_rank(record: CommitRecord, seed: int) -> str:
    value = f"{seed}|{record.group_id}".encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def select_balanced_synthetic(records: Iterable[CommitRecord], per_cwe: int, seed: int) -> list[CommitRecord]:
    """Select a deterministic, marginally balanced subset for each CWE."""
    selected: list[CommitRecord] = []
    by_mode: dict[str, list[CommitRecord]] = defaultdict(list)
    for record in records:
        by_mode[record.mode].append(record)
    for mode in CANONICAL_MODES:
        candidates = sorted(by_mode[mode], key=lambda item: _stable_rank(item, seed))
        if len(candidates) < per_cwe:
            raise ValueError(f"{mode}: need {per_cwe} synthetic commits but found {len(candidates)}")
        counts: dict[tuple[str, str], Counter[str]] = {
            (field, mode): Counter() for field in CONTEXT_FIELDS
        }
        chosen: list[CommitRecord] = []
        remaining = candidates[:]
        while len(chosen) < per_cwe:
            def score(item: CommitRecord) -> tuple[Any, ...]:
                values = tuple(counts[(field, mode)][item.context[field]] for field in CONTEXT_FIELDS)
                full = tuple(item.context[field] for field in CONTEXT_FIELDS)
                full_count = sum(
                    1 for existing in chosen
                    if tuple(existing.context[field] for field in CONTEXT_FIELDS) == full
                )
                return (full_count, *values, _stable_rank(item, seed))

            current = min(remaining, key=score)
            remaining.remove(current)
            chosen.append(current)
            for field in CONTEXT_FIELDS:
                counts[(field, mode)][current.context[field]] += 1
        selected.extend(chosen)
    return selected


def select_real_cap(records: Iterable[CommitRecord], per_cwe: int, seed: int) -> list[CommitRecord]:
    by_mode: dict[str, list[CommitRecord]] = defaultdict(list)
    for record in records:
        by_mode[record.mode].append(record)
    selected: list[CommitRecord] = []
    for mode in CANONICAL_MODES:
        grouped: dict[str, list[CommitRecord]] = defaultdict(list)
        for record in by_mode[mode]:
            grouped[record.group_id].append(record)
        commit_groups = sorted(grouped.values(), key=lambda items: _stable_rank(items[0], seed))
        for records_for_commit in commit_groups[: min(per_cwe, len(commit_groups))]:
            selected.extend(records_for_commit)
    return selected


def split_commits(records: Iterable[CommitRecord], seed: int) -> dict[str, str]:
    """Return deterministic train/validation/test assignments grouped by commit."""
    assignments: dict[str, str] = {}
    by_dataset_mode: dict[tuple[str, str], list[CommitRecord]] = defaultdict(list)
    for record in records:
        key = (record.dataset, record.mode)
        if not any(existing.group_id == record.group_id for existing in by_dataset_mode[key]):
            by_dataset_mode[key].append(record)
    for key, group in by_dataset_mode.items():
        ordered = sorted(group, key=lambda item: _stable_rank(item, seed))
        n = len(ordered)
        train_end = max(1, int(n * 0.70)) if n else 0
        validation_end = max(train_end + 1, int(n * 0.85)) if n >= 3 else train_end
        validation_end = min(validation_end, n - 1) if n >= 3 else validation_end
        for index, record in enumerate(ordered):
            assignments[record.group_id] = "train" if index < train_end else "validation" if index < validation_end else "test"
    return assignments


def token_windows(record: CommitRecord, window_size: int = 200, stride: int = 5) -> list[dict[str, Any]]:
    matches = token_matches(record.source)
    if not matches:
        return []
    spans = badpart_spans(record.source, record.badparts)
    windows: list[dict[str, Any]] = []
    for start in window_start_indexes(len(matches), window_size, stride):
        tokens = matches[start : start + window_size]
        if not tokens:
            continue
        first, last = tokens[0].start(), tokens[-1].end()
        label = int(any(first < end and start_pos < last for start_pos, end in spans))
        windows.append(
            {
                "group_id": record.group_id,
                "dataset": record.dataset,
                "mode": record.mode,
                "commit_id": record.commit_id,
                "repo": record.repo,
                "filename": record.filename,
                "context": record.context,
                "tokens": [match.group(0) for match in tokens],
                "label": label,
            }
        )
    return windows


def cap_windows(
    windows: Iterable[dict[str, Any]],
    maximum_positive: int,
    maximum_negative: int,
    seed: int,
) -> list[dict[str, Any]]:
    """Keep a deterministic, bounded class-balanced set of windows per file."""
    by_label: dict[int, list[dict[str, Any]]] = {0: [], 1: []}
    for window in windows:
        by_label[int(window["label"])].append(window)
    selected: list[dict[str, Any]] = []
    for label, maximum in ((1, maximum_positive), (0, maximum_negative)):
        ranked = sorted(
            by_label[label],
            key=lambda item: hashlib.sha256(
                f"{seed}|{item['group_id']}|{item['filename']}|{label}|{' '.join(item['tokens'])}".encode("utf-8")
            ).hexdigest(),
        )
        selected.extend(ranked[:maximum])
    return selected


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def select_audit_pairs(records: Iterable[CommitRecord], per_cwe: int, seed: int) -> list[dict[str, Any]]:
    """Select diverse human-review candidates without asserting that review occurred."""
    result: list[dict[str, Any]] = []
    by_mode: dict[str, list[CommitRecord]] = defaultdict(list)
    for record in records:
        by_mode[record.mode].append(record)
    for mode in CANONICAL_MODES:
        pool = sorted(by_mode[mode], key=lambda item: _stable_rank(item, seed))
        used: set[tuple[str, ...]] = set()
        selected: list[CommitRecord] = []
        for record in pool:
            signature = tuple(record.context[field] for field in CONTEXT_FIELDS)
            if signature not in used or len(pool) - len(selected) <= per_cwe - len(selected):
                selected.append(record)
                used.add(signature)
            if len(selected) == per_cwe:
                break
        for record in selected:
            result.append({
                "id": record.commit_id,
                "mode": record.mode,
                "filename": record.filename,
                "context": record.context,
                "vulnerable_code": record.source,
                "fixed_code": record.fixed_source,
                "review_status": "pending_manual_review",
            })
    return result
