from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .cwe_registry import all_cwes
from .diff_utils import extract_changed_parts
from .storage import read_jsonl


def export_records(records: list[dict[str, Any]], out_dir: Path) -> dict[str, int]:
    out_dir.mkdir(parents=True, exist_ok=True)
    by_mode: dict[str, dict[str, dict[str, Any]]] = {definition.mode: {} for definition in all_cwes()}

    for record in records:
        mode = str(record.get("mode") or record.get("context", {}).get("mode", "unknown"))
        if mode not in by_mode:
            by_mode[mode] = {}
        repo_name = f"synvulcommit/{mode}"
        commit_id = str(record.get("id", f"sample_{len(by_mode[mode]) + 1:06d}"))
        filename = str(record.get("filename", "app.py"))
        diff_text = str(record.get("diff", ""))
        badparts = list(record.get("badparts") or [])
        goodparts = list(record.get("goodparts") or [])
        if not badparts or not goodparts:
            badparts, goodparts = extract_changed_parts(diff_text)

        repo = by_mode[mode].setdefault(repo_name, {})
        repo[commit_id] = {
            "msg": str(record.get("commit_message", "")),
            "synvulcommit": {
                "id": record.get("id"),
                "cwe": record.get("cwe"),
                "cwe_name": record.get("cwe_name"),
                "context": record.get("context", {}),
                "validation": record.get("validation", {}),
            },
            "files": {
                filename: {
                    "source": "\n" + str(record.get("vulnerable_code", "")).strip() + "\n",
                    "sourceWithComments": str(record.get("vulnerable_code", "")).strip() + "\n",
                    "sourcecodeafter": str(record.get("fixed_code", "")).strip() + "\n",
                    "changes": [
                        {
                            "diff": diff_text,
                            "add": len(goodparts),
                            "remove": len(badparts),
                            "filename": filename,
                            "badparts": badparts,
                            "goodparts": goodparts,
                        }
                    ],
                }
            },
        }

    counts: dict[str, int] = {}
    for definition in all_cwes():
        mode = definition.mode
        path = out_dir / f"plain_{mode}"
        data = by_mode.get(mode, {})
        counts[mode] = sum(len(commits) for commits in data.values())
        path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description="Export SynVulCommit JSONL records to VUDENC-style plain_<mode> files.")
    parser.add_argument("--input", default="output/samples.jsonl", help="Input JSONL dataset path.")
    parser.add_argument("--out", default="output/vudenc", help="Output directory for plain_<mode> files.")
    args = parser.parse_args()

    records = read_jsonl(Path(args.input))
    counts = export_records(records, Path(args.out))
    for mode, count in counts.items():
        print(f"exported {count:4d} samples to plain_{mode}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
