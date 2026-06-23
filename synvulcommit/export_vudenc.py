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
    metadata_rows: list[dict[str, Any]] = []
    row_counts: dict[str, int] = {}

    for record in records:
        mode = str(record.get("mode") or record.get("context", {}).get("mode", "unknown"))
        if mode not in by_mode:
            by_mode[mode] = {}
        row_counts[mode] = row_counts.get(mode, 0) + 1
        row_index = row_counts[mode]
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
                "provenance": _provenance(record),
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
        metadata_rows.append(
            {
                "id": record.get("id"),
                "cwe": record.get("cwe"),
                "cwe_name": record.get("cwe_name"),
                "mode": mode,
                "plain_file": f"plain_{mode}",
                "row_index": row_index,
                "repo": repo_name,
                "commit_id": commit_id,
                "filename": filename,
                "provenance": _provenance(record),
                "validation_summary": record.get("validation_summary") or _validation_summary(record.get("validation", {})),
            }
        )

    counts: dict[str, int] = {}
    for definition in all_cwes():
        mode = definition.mode
        path = out_dir / f"plain_{mode}"
        data = by_mode.get(mode, {})
        counts[mode] = sum(len(commits) for commits in data.values())
        path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    metadata_path = out_dir / "metadata.jsonl"
    with metadata_path.open("w", encoding="utf-8") as handle:
        for row in metadata_rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    return counts


def _provenance(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": record.get("provider"),
        "model": record.get("model"),
        "prompt_sha256": record.get("prompt_sha256"),
        "seed": record.get("seed"),
        "attempt": record.get("attempt"),
        "generated_at": record.get("generated_at"),
    }


def _validation_summary(validation: Any) -> dict[str, Any]:
    if not isinstance(validation, dict):
        return {"passed": False, "reason_count": 0, "bandit_findings": 0, "semgrep_findings": 0}
    return {
        "passed": bool(validation.get("passed")),
        "reason_count": len(validation.get("reasons") or []),
        "bandit_findings": _tool_finding_count(validation, "bandit"),
        "semgrep_findings": _tool_finding_count(validation, "semgrep"),
    }


def _tool_finding_count(validation: dict[str, Any], tool_name: str) -> int:
    legacy_tool_results = validation.get("tool_results", {})
    if isinstance(legacy_tool_results, dict) and tool_name in legacy_tool_results:
        legacy_result = legacy_tool_results.get(tool_name, {})
        if isinstance(legacy_result, dict):
            legacy_findings = legacy_result.get("findings", [])
            if isinstance(legacy_findings, list):
                return len(legacy_findings)

    total = 0
    for suffix in ("before", "after"):
        result = validation.get(f"{tool_name}_{suffix}", {})
        if not isinstance(result, dict):
            continue
        findings = result.get("findings", [])
        if isinstance(findings, list):
            total += len(findings)
    return total


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
