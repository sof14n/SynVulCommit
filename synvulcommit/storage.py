from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def ensure_output_files(output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    samples_path = output_dir / "samples.jsonl"
    rejected_path = output_dir / "rejected.jsonl"
    samples_path.touch(exist_ok=True)
    rejected_path.touch(exist_ok=True)
    return samples_path, rejected_path


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                records.append(json.loads(stripped))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at {path}:{line_number}: {exc}") from exc
    return records


def next_sample_id(records: list[dict[str, Any]], cwe: str, mode: str) -> str:
    prefix = f"{cwe}_{mode}_"
    pattern = re.compile(rf"^{re.escape(prefix)}(\d+)$")
    suffixes = [
        int(match.group(1))
        for record in records
        if (match := pattern.match(str(record.get("id", ""))))
    ]
    return f"{prefix}{max(suffixes, default=0) + 1:06d}"
