from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class VudencFileRecord:
    mode: str
    repo: str
    commit_id: str
    filename: str
    source: str
    badparts: tuple[str, ...]
    origin: str

    @property
    def group_id(self) -> str:
        return f"{self.origin}:{self.mode}:{self.repo}:{self.commit_id}"


def load_modes(root: Path, modes: list[str], origin: str) -> list[VudencFileRecord]:
    records: list[VudencFileRecord] = []
    for mode in modes:
        records.extend(load_plain_file(root / f"plain_{mode}", mode=mode, origin=origin))
    return records


def load_plain_file(path: Path, mode: str, origin: str) -> list[VudencFileRecord]:
    if not path.exists():
        raise FileNotFoundError(f"missing VUDENC plain file: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"expected object in {path}")

    records: list[VudencFileRecord] = []
    for repo, commits in data.items():
        if not isinstance(commits, dict):
            continue
        for commit_id, commit in commits.items():
            files = commit.get("files", {}) if isinstance(commit, dict) else {}
            if not isinstance(files, dict):
                continue
            for filename, file_data in files.items():
                if not isinstance(file_data, dict):
                    continue
                source = str(file_data.get("source") or file_data.get("sourceWithComments") or "")
                badparts = _collect_badparts(file_data.get("changes", []))
                if source.strip() and badparts:
                    records.append(
                        VudencFileRecord(
                            mode=mode,
                            repo=str(repo),
                            commit_id=str(commit_id),
                            filename=str(filename),
                            source=source,
                            badparts=tuple(badparts),
                            origin=origin,
                        )
                    )
    return records


def _collect_badparts(changes: Any) -> list[str]:
    values: list[str] = []
    if not isinstance(changes, list):
        return values
    for change in changes:
        if not isinstance(change, dict):
            continue
        badparts = change.get("badparts", [])
        if not isinstance(badparts, list):
            continue
        for badpart in badparts:
            text = str(badpart).strip()
            if text and text not in values:
                values.append(text)
    return values

