from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from .cwe_registry import all_cwes
from .diff_utils import extract_changed_parts, make_unified_diff
from .storage import read_jsonl


_CONTEXT_FIELDS = (
    "cwe_key",
    "cwe",
    "cwe_name",
    "mode",
    "application_type",
    "flow_pattern",
    "difficulty",
    "structure",
    "sample_index",
)
_PROVENANCE_FIELDS = ("provider", "model", "prompt_sha256", "seed", "attempt", "generated_at")
_UNSAFE_METADATA = re.compile(
    r"(?:api[_-]?key|authorization|bearer\s|https?://|[A-Za-z]:[\\/]|(?:^|[\\/])(?:users|home|tmp|temp)(?:[\\/]|$))",
    re.IGNORECASE,
)
_TOOL_STATUSES = {"success", "missing", "timeout", "error", "unavailable", "unknown"}


def export_records(records: list[dict[str, Any]], out_dir: Path) -> dict[str, int]:
    out_dir.mkdir(parents=True, exist_ok=True)
    by_mode, metadata_rows, counts = build_export_payloads(records)

    for definition in all_cwes():
        mode = definition.mode
        path = out_dir / f"plain_{mode}"
        path.write_text(json.dumps(by_mode.get(mode, {}), indent=2, sort_keys=True), encoding="utf-8")

    metadata_path = out_dir / "metadata.jsonl"
    with metadata_path.open("w", encoding="utf-8") as handle:
        for row in metadata_rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    return counts


def build_export_payloads(
    records: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, dict[str, Any]]], list[dict[str, Any]], dict[str, int]]:
    by_mode: dict[str, dict[str, dict[str, Any]]] = {definition.mode: {} for definition in all_cwes()}
    metadata_rows: list[dict[str, Any]] = []
    row_counts: dict[str, int] = {}

    for record in records:
        mode = str(record.get("mode") or record.get("context", {}).get("mode", "unknown"))
        if mode not in by_mode:
            by_mode[mode] = {}
        row_counts[mode] = row_counts.get(mode, 0) + 1
        row_index = row_counts[mode]
        safe_mode = _safe_text(mode) or "unknown"
        repo_name = f"synvulcommit/{safe_mode}"
        commit_id = _safe_text(record.get("id")) or f"sample_{len(by_mode[mode]) + 1:06d}"
        filename = _relative_filename(record.get("filename"))
        diff_text = str(record.get("diff", ""))
        if _contains_unsafe_metadata(diff_text):
            diff_text = make_unified_diff(
                str(record.get("vulnerable_code", "")),
                str(record.get("fixed_code", "")),
                filename,
            )
        badparts = list(record.get("badparts") or [])
        goodparts = list(record.get("goodparts") or [])
        if not badparts or not goodparts:
            badparts, goodparts = extract_changed_parts(diff_text)

        repo = by_mode[mode].setdefault(repo_name, {})
        repo[commit_id] = {
            "msg": _safe_text(record.get("commit_message")) or "Synthetic security fix",
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
            _build_metadata_row(
                record=record,
                mode=safe_mode,
                row_index=row_index,
                repo_name=repo_name,
                commit_id=commit_id,
                filename=filename,
            )
        )

    counts = {
        definition.mode: sum(len(commits) for commits in by_mode.get(definition.mode, {}).values())
        for definition in all_cwes()
    }
    return by_mode, metadata_rows, counts


def _build_metadata_row(
    record: dict[str, Any],
    mode: str,
    row_index: int,
    repo_name: str,
    commit_id: str,
    filename: str,
) -> dict[str, Any]:
    metadata = {
        "id": _safe_text(record.get("id")) or commit_id,
        "cwe": _safe_text(record.get("cwe")) or "unknown",
        "cwe_name": _safe_text(record.get("cwe_name")) or "unknown",
        "mode": mode,
        "plain_file": f"plain_{mode}",
        "row_index": row_index,
        "repo": repo_name,
        "commit_id": commit_id,
        "filename": filename,
        "context": _allowlisted_context(record.get("context")),
        "provenance": _allowlisted_provenance(record),
        "validation_summary": _validation_summary(record.get("validation")),
    }
    review_summary = _review_summary(record.get("review"))
    if review_summary:
        metadata["review_summary"] = review_summary
    return metadata


def _allowlisted_context(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    context: dict[str, Any] = {}
    for field in _CONTEXT_FIELDS:
        safe_value = _safe_scalar(value.get(field))
        if safe_value is not None:
            context[field] = safe_value
    return context


def _allowlisted_provenance(record: dict[str, Any]) -> dict[str, Any]:
    provenance: dict[str, Any] = {}
    for field in _PROVENANCE_FIELDS:
        safe_value = _safe_scalar(record.get(field))
        if safe_value is not None:
            provenance[field] = safe_value
    return provenance


def _validation_summary(value: Any) -> dict[str, Any]:
    validation = value if isinstance(value, dict) else {}
    structural = validation.get("structural")
    structural = structural if isinstance(structural, dict) else {}
    return {
        "passed": bool(validation.get("passed")),
        "reason_count": _list_length(validation.get("reasons")),
        "warning_count": _list_length(validation.get("warnings")),
        "structural": {
            "passed": bool(structural.get("passed")),
            "vulnerable_markers": _safe_string_list(structural.get("vulnerable_markers")),
            "fixed_markers": _safe_string_list(structural.get("fixed_markers")),
        },
        "bandit": _tool_summary(validation, "bandit"),
        "semgrep": _tool_summary(validation, "semgrep"),
    }


def _review_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    summary: dict[str, Any] = {}
    required = value.get("required")
    if isinstance(required, bool):
        summary["required"] = required
    for field in ("status", "verdict", "reason_category", "provider", "model"):
        safe_value = _safe_text(value.get(field))
        if safe_value is not None:
            summary[field] = safe_value
    for field in ("cwe_correct", "fix_correct", "context_correct", "runtime_plausible"):
        if isinstance(value.get(field), bool):
            summary[field] = value[field]
    return summary


def _tool_summary(validation: dict[str, Any], tool_name: str) -> dict[str, Any]:
    return {
        "before": _tool_run_summary(_tool_run(validation, tool_name, "before"), tool_name),
        "after": _tool_run_summary(_tool_run(validation, tool_name, "after"), tool_name),
    }


def _tool_run(validation: dict[str, Any], tool_name: str, phase: str) -> dict[str, Any]:
    direct = validation.get(f"{tool_name}_{phase}")
    if isinstance(direct, dict):
        return direct
    tool_results = validation.get("tool_results")
    if not isinstance(tool_results, dict):
        return {}
    tool_result = tool_results.get(tool_name)
    if not isinstance(tool_result, dict):
        return {}
    phased = tool_result.get(phase)
    return phased if isinstance(phased, dict) else tool_result


def _tool_run_summary(tool_run: dict[str, Any], tool_name: str) -> dict[str, Any]:
    status = str(tool_run.get("status") or ("success" if tool_run.get("available") else "unavailable"))
    if status not in _TOOL_STATUSES:
        status = "unknown"
    return {
        "status": status,
        "finding_ids": _finding_ids(tool_run.get("findings"), tool_name),
    }


def _finding_ids(value: Any, tool_name: str) -> list[str]:
    if not isinstance(value, list):
        return []
    field = "test_id" if tool_name == "bandit" else "check_id"
    identifiers = {_safe_text(item.get(field)) for item in value if isinstance(item, dict)}
    return sorted(identifier for identifier in identifiers if identifier)


def _safe_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [safe for item in value if (safe := _safe_text(item))]


def _list_length(value: Any) -> int:
    return len(value) if isinstance(value, list) else 0


def _safe_scalar(value: Any) -> str | int | float | bool | None:
    if isinstance(value, (bool, int, float)):
        return value
    return _safe_text(value)


def _safe_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or _contains_unsafe_metadata(text):
        return None
    return text


def _contains_unsafe_metadata(value: str) -> bool:
    return bool(_UNSAFE_METADATA.search(value))


def _relative_filename(value: Any) -> str:
    filename = str(value or "app.py").strip().replace("\\", "/")
    if not filename or filename.startswith("/") or re.match(r"^[A-Za-z]:/", filename) or ".." in filename.split("/"):
        filename = filename.rsplit("/", maxsplit=1)[-1]
    return filename or "app.py"


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
