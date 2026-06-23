from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .cwe_registry import all_cwes
from .diversity import make_code_pair_hash
from .storage import read_jsonl


REQUIRED_SAMPLE_FIELDS = (
    "id",
    "cwe",
    "cwe_name",
    "mode",
    "context",
    "attempt",
    "commit_message",
    "filename",
    "vulnerable_code",
    "fixed_code",
    "diff",
    "badparts",
    "goodparts",
    "provider",
    "model",
    "validation",
    "prompt_sha256",
    "seed",
    "generated_at",
    "validation_summary",
)


def verify_dataset(input_path: Path, rejected_path: Path | None = None, vudenc_dir: Path | None = None) -> dict[str, Any]:
    samples = read_jsonl(input_path)
    rejected = read_jsonl(rejected_path) if rejected_path else None
    errors: list[str] = []

    duplicate_sample_ids = _duplicates(str(record.get("id", "")) for record in samples)
    duplicate_code_fingerprints = _duplicate_code_fingerprints(samples)
    missing_required_fields = _missing_required_fields(samples)
    vudenc_integrity = _verify_vudenc(samples, vudenc_dir) if vudenc_dir else _empty_vudenc_integrity()

    errors.extend(f"duplicate sample id: {sample_id}" for sample_id in duplicate_sample_ids)
    errors.extend(
        f"duplicate code fingerprint: {item['fingerprint']} ids={','.join(item['ids'])}"
        for item in duplicate_code_fingerprints
    )
    errors.extend(
        f"missing required field: {item['id']} field={item['field']}"
        for item in missing_required_fields
    )
    errors.extend(vudenc_integrity["errors"])

    rejected_total = len(rejected) if rejected is not None else None
    accepted_total = len(samples)
    attempted_total = accepted_total + rejected_total if rejected_total is not None else None
    return {
        "status": "failed" if errors else "passed",
        "input": str(input_path),
        "rejected_log": str(rejected_path) if rejected_path else None,
        "vudenc_dir": str(vudenc_dir) if vudenc_dir else None,
        "accepted_total": accepted_total,
        "accepted_by_cwe": _accepted_by_cwe(samples),
        "rejected_total": rejected_total,
        "attempted_total": attempted_total,
        "acceptance_rate": (accepted_total / attempted_total) if attempted_total else None,
        "average_attempts_per_accepted": _average_attempts(samples),
        "top_rejection_reasons": _top_rejection_reasons(rejected or []),
        "validation_tool_findings": _validation_tool_findings(samples),
        "duplicate_sample_ids": duplicate_sample_ids,
        "duplicate_code_fingerprints": duplicate_code_fingerprints,
        "missing_required_fields": missing_required_fields,
        "vudenc_integrity": vudenc_integrity,
        "error_count": len(errors),
        "errors": errors,
    }


def _accepted_by_cwe(samples: list[dict[str, Any]]) -> dict[str, int]:
    counts = {definition.cwe: 0 for definition in all_cwes()}
    for record in samples:
        cwe = str(record.get("cwe", "unknown") or "unknown")
        counts[cwe] = counts.get(cwe, 0) + 1
    return dict(sorted(counts.items()))


def _average_attempts(samples: list[dict[str, Any]]) -> float | None:
    attempts: list[float] = []
    for record in samples:
        try:
            attempts.append(float(record.get("attempt", 0)))
        except (TypeError, ValueError):
            continue
    if not attempts:
        return None
    return round(sum(attempts) / len(attempts), 6)


def _top_rejection_reasons(rejected: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    for record in rejected:
        reasons = record.get("reject_reason", [])
        if isinstance(reasons, str):
            reasons = [reasons]
        if not isinstance(reasons, list):
            reasons = ["<invalid reject_reason>"]
        for reason in reasons:
            counts[str(reason)] += 1
    return [{"reason": reason, "count": count} for reason, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]]


def _validation_tool_findings(samples: list[dict[str, Any]]) -> dict[str, int]:
    totals = {"bandit": 0, "semgrep": 0}
    for record in samples:
        validation = record.get("validation", {})
        if not isinstance(validation, dict):
            continue
        for tool_name in totals:
            totals[tool_name] += _tool_finding_count(validation, tool_name)
    return totals


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


def _duplicates(values: Any) -> list[str]:
    counts: Counter[str] = Counter(value for value in values if value)
    return sorted(value for value, count in counts.items() if count > 1)


def _duplicate_code_fingerprints(samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ids_by_hash: dict[str, list[str]] = {}
    for record in samples:
        fingerprint = make_code_pair_hash(record)
        ids_by_hash.setdefault(fingerprint, []).append(str(record.get("id", "")))
    return [
        {"fingerprint": fingerprint, "ids": sorted(ids)}
        for fingerprint, ids in sorted(ids_by_hash.items())
        if len(set(ids)) > 1
    ]


def _missing_required_fields(samples: list[dict[str, Any]]) -> list[dict[str, str]]:
    missing: list[dict[str, str]] = []
    for index, record in enumerate(samples, start=1):
        sample_id = str(record.get("id") or f"<row:{index}>")
        for field in REQUIRED_SAMPLE_FIELDS:
            if field not in record or _is_empty_required_value(record[field]):
                missing.append({"id": sample_id, "field": field})
    return missing


def _is_empty_required_value(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, dict)):
        return not value
    return False


def _verify_vudenc(samples: list[dict[str, Any]], vudenc_dir: Path) -> dict[str, Any]:
    expected_by_mode: dict[str, set[str]] = {}
    for record in samples:
        mode = str(record.get("mode") or record.get("context", {}).get("mode", "unknown"))
        expected_by_mode.setdefault(mode, set()).add(str(record.get("id", "")))

    plain_counts: dict[str, int] = {}
    missing_in_plain: list[str] = []
    extra_in_plain: list[str] = []
    errors: list[str] = []

    for definition in all_cwes():
        mode = definition.mode
        path = vudenc_dir / f"plain_{mode}"
        if not path.exists():
            errors.append(f"missing VUDENC file: plain_{mode}")
            plain_counts[mode] = 0
            missing_in_plain.extend(sorted(expected_by_mode.get(mode, set())))
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"invalid VUDENC JSON: plain_{mode}: {exc}")
            plain_counts[mode] = 0
            continue
        ids = _commit_ids_from_plain(data)
        plain_counts[mode] = len(ids)
        expected_ids = expected_by_mode.get(mode, set())
        missing_in_plain.extend(sorted(expected_ids - ids))
        extra_in_plain.extend(sorted(ids - expected_ids))

    metadata_integrity = _verify_metadata(samples, vudenc_dir / "metadata.jsonl")
    errors.extend(f"sample missing from VUDENC plain files: {sample_id}" for sample_id in missing_in_plain)
    errors.extend(f"unexpected sample in VUDENC plain files: {sample_id}" for sample_id in extra_in_plain)
    errors.extend(metadata_integrity["errors"])

    return {
        "checked": True,
        "plain_counts": dict(sorted(plain_counts.items())),
        "metadata_rows": metadata_integrity["metadata_rows"],
        "missing_in_plain": missing_in_plain,
        "extra_in_plain": extra_in_plain,
        "metadata_missing_ids": metadata_integrity["metadata_missing_ids"],
        "metadata_extra_ids": metadata_integrity["metadata_extra_ids"],
        "metadata_row_mismatches": metadata_integrity["metadata_row_mismatches"],
        "errors": errors,
    }


def _empty_vudenc_integrity() -> dict[str, Any]:
    return {
        "checked": False,
        "plain_counts": {},
        "metadata_rows": 0,
        "missing_in_plain": [],
        "extra_in_plain": [],
        "metadata_missing_ids": [],
        "metadata_extra_ids": [],
        "metadata_row_mismatches": [],
        "errors": [],
    }


def _commit_ids_from_plain(data: Any) -> set[str]:
    if not isinstance(data, dict):
        return set()
    ids: set[str] = set()
    for commits in data.values():
        if isinstance(commits, dict):
            ids.update(str(commit_id) for commit_id in commits.keys())
    return ids


def _verify_metadata(samples: list[dict[str, Any]], metadata_path: Path) -> dict[str, Any]:
    expected_ids = {str(record.get("id", "")) for record in samples}
    if not metadata_path.exists():
        return {
            "metadata_rows": 0,
            "metadata_missing_ids": sorted(expected_ids),
            "metadata_extra_ids": [],
            "metadata_row_mismatches": [],
            "errors": ["missing VUDENC metadata.jsonl"],
        }
    try:
        rows = read_jsonl(metadata_path)
    except ValueError as exc:
        return {
            "metadata_rows": 0,
            "metadata_missing_ids": sorted(expected_ids),
            "metadata_extra_ids": [],
            "metadata_row_mismatches": [],
            "errors": [str(exc)],
        }
    ids = [str(row.get("id", "")) for row in rows]
    row_ids = set(ids)
    missing = sorted(expected_ids - row_ids)
    extra = sorted(row_ids - expected_ids)
    mismatches = _metadata_row_mismatches(rows)
    errors = [f"sample missing from VUDENC metadata: {sample_id}" for sample_id in missing]
    errors.extend(f"unexpected sample in VUDENC metadata: {sample_id}" for sample_id in extra)
    errors.extend(f"metadata row mismatch: {item}" for item in mismatches)
    if len(rows) != len(samples):
        errors.append(f"metadata row count mismatch: expected={len(samples)} actual={len(rows)}")
    return {
        "metadata_rows": len(rows),
        "metadata_missing_ids": missing,
        "metadata_extra_ids": extra,
        "metadata_row_mismatches": mismatches,
        "errors": errors,
    }


def _metadata_row_mismatches(rows: list[dict[str, Any]]) -> list[str]:
    mismatches: list[str] = []
    for index, row in enumerate(rows, start=1):
        sample_id = str(row.get("id", ""))
        mode = str(row.get("mode", ""))
        plain_file = str(row.get("plain_file", ""))
        commit_id = str(row.get("commit_id", ""))
        row_index = row.get("row_index")
        if plain_file != f"plain_{mode}":
            mismatches.append(f"{sample_id}: plain_file")
        if commit_id != sample_id:
            mismatches.append(f"{sample_id}: commit_id")
        if not isinstance(row_index, int) or row_index < 1:
            mismatches.append(f"{sample_id or '<row:' + str(index) + '>'}: row_index")
    return mismatches


def print_human_report(metrics: dict[str, Any]) -> None:
    print(f"dataset status: {metrics['status']}")
    print(f"accepted total: {metrics['accepted_total']}")
    print("accepted by CWE:")
    for cwe, count in metrics["accepted_by_cwe"].items():
        print(f"  {cwe}: {count}")
    if metrics["rejected_total"] is not None:
        print(f"rejected total: {metrics['rejected_total']}")
        print(f"acceptance rate: {metrics['acceptance_rate']:.6f}")
    print(f"average attempts per accepted: {metrics['average_attempts_per_accepted']}")
    print(f"validation findings: bandit={metrics['validation_tool_findings']['bandit']} semgrep={metrics['validation_tool_findings']['semgrep']}")
    print(f"duplicate sample ids: {len(metrics['duplicate_sample_ids'])}")
    print(f"duplicate code fingerprints: {len(metrics['duplicate_code_fingerprints'])}")
    print(f"missing required fields: {len(metrics['missing_required_fields'])}")
    if metrics["vudenc_integrity"]["checked"]:
        print(f"vudenc metadata rows: {metrics['vudenc_integrity']['metadata_rows']}")
        print(f"vudenc errors: {len(metrics['vudenc_integrity']['errors'])}")
    if metrics["top_rejection_reasons"]:
        print("top rejection reasons:")
        for item in metrics["top_rejection_reasons"]:
            print(f"  {item['count']:4d} {item['reason']}")
    if metrics["errors"]:
        print("errors:")
        for error in metrics["errors"]:
            print(f"  {error}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify SynVulCommit JSONL and VUDENC export integrity.")
    parser.add_argument("--input", default="output/samples.jsonl", help="Input accepted samples JSONL path.")
    parser.add_argument("--rejected", help="Optional rejected samples JSONL path.")
    parser.add_argument("--vudenc", help="Optional VUDENC export directory.")
    parser.add_argument("--json", action="store_true", help="Print stable machine-readable metrics.")
    args = parser.parse_args()

    metrics = verify_dataset(
        input_path=Path(args.input),
        rejected_path=Path(args.rejected) if args.rejected else None,
        vudenc_dir=Path(args.vudenc) if args.vudenc else None,
    )
    if args.json:
        print(json.dumps(metrics, indent=2, sort_keys=True))
    else:
        print_human_report(metrics)
    return 0 if metrics["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
