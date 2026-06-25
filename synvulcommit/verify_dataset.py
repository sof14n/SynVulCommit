from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from .cwe_registry import all_cwes, all_semgrep_rule_ids
from .diversity import DiversityIndex
from .export_vudenc import build_export_payloads
from .spec_sampler import CONTEXT_DIMENSIONS
from .storage import read_jsonl


TOOL_STATUSES = {"success", "missing", "timeout", "error", "unavailable", "unknown"}
SAFE_VALUE = re.compile(r"^[A-Za-z0-9_.:-]+$")
SYNVUL_SEMGREP_RULE_IDS = all_semgrep_rule_ids()


def verify_dataset(
    accepted_records: list[dict[str, Any]],
    rejected_records: list[dict[str, Any]],
    vudenc_dir: Path,
    initial_errors: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    errors = list(initial_errors or [])
    coverage = _coverage_summary(accepted_records)
    duplicates, duplicate_errors = _duplicate_summary(accepted_records)
    validation, validation_errors = _validation_summary(accepted_records)
    review, review_errors = _review_summary(accepted_records, rejected_records)
    rejection_summary = _rejection_summary(rejected_records)
    integrity = _export_integrity(accepted_records, vudenc_dir)
    errors.extend(duplicate_errors)
    errors.extend(validation_errors)
    errors.extend(review_errors)
    errors.extend(integrity["errors"])

    return {
        "schema_version": 1,
        "status": "pass" if not errors else "fail",
        "error_count": len(errors),
        "accepted": coverage,
        "duplicates": duplicates,
        "validation": validation,
        "review": review,
        "rejections": rejection_summary,
        "export_integrity": integrity,
        "errors": errors,
    }


def verify_paths(input_path: Path, rejected_path: Path, vudenc_dir: Path) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    accepted_records = _read_records(input_path, "accepted_input", errors)
    rejected_records = _read_records(rejected_path, "rejected_input", errors)
    return verify_dataset(accepted_records, rejected_records, vudenc_dir, errors)


def write_verification_report(report: dict[str, Any], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _coverage_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    definitions = {definition.mode: definition for definition in all_cwes()}
    by_cwe: dict[str, dict[str, Any]] = {
        definition.mode: {
            "cwe": definition.cwe,
            "accepted": 0,
            "context": {dimension: Counter() for dimension in CONTEXT_DIMENSIONS},
            "context_tuples": Counter(),
        }
        for definition in all_cwes()
    }
    for record in records:
        mode = _record_mode(record)
        if mode not in by_cwe:
            by_cwe[mode] = {
                "cwe": definitions.get(mode).cwe if mode in definitions else "unknown",
                "accepted": 0,
                "context": {dimension: Counter() for dimension in CONTEXT_DIMENSIONS},
                "context_tuples": Counter(),
            }
        bucket = by_cwe[mode]
        context = record.get("context") if isinstance(record.get("context"), dict) else {}
        values = [_safe_value(context.get(dimension)) for dimension in CONTEXT_DIMENSIONS]
        bucket["accepted"] += 1
        for dimension, value in zip(CONTEXT_DIMENSIONS, values, strict=True):
            bucket["context"][dimension][value] += 1
        bucket["context_tuples"]["|".join(values)] += 1

    return {
        "total": len(records),
        "by_cwe": {
            mode: {
                "cwe": bucket["cwe"],
                "accepted": bucket["accepted"],
                "context": {key: _sorted_counts(value) for key, value in bucket["context"].items()},
                "context_tuples": _sorted_counts(bucket["context_tuples"]),
            }
            for mode, bucket in sorted(by_cwe.items())
        },
    }


def _duplicate_summary(records: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, str]]]:
    index = DiversityIndex()
    counts: Counter[str] = Counter()
    errors: list[dict[str, str]] = []
    for record in records:
        accepted, _ = index.accepts(record)
        if accepted:
            continue
        check = _safe_check((index.last_rejection or {}).get("check"))
        counts[check] += 1
        errors.append(_issue("accepted_duplicate", sample_id=record.get("id"), mode=_record_mode(record)))

    total = len(records)
    checks = ("exact_code_pair", "normalized_ast", "near_duplicate")
    return (
        {
            "accepted": {
                "checked": total,
                "policy_ordered": {
                    check: {"count": counts[check], "rate": _rate(counts[check], total)} for check in checks
                },
                "other": {key: value for key, value in _sorted_counts(counts).items() if key not in checks},
            }
        },
        errors,
    )


def _validation_summary(records: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, str]]]:
    overall: Counter[str] = Counter()
    structural: Counter[str] = Counter()
    tool_statuses = {
        tool: {phase: Counter() for phase in ("before", "after")}
        for tool in ("bandit", "semgrep")
    }
    warning_records = 0
    warning_count = 0
    post_fix_synvul_rule_ids: Counter[str] = Counter()
    errors: list[dict[str, str]] = []

    for record in records:
        validation = record.get("validation")
        mode = _record_mode(record)
        sample_id = record.get("id")
        if not isinstance(validation, dict):
            overall["missing"] += 1
            structural["missing"] += 1
            errors.append(_issue("missing_validation", sample_id=sample_id, mode=mode))
            continue

        if validation.get("passed") is True:
            overall["passed"] += 1
        else:
            overall["failed"] += 1
            errors.append(_issue("failed_validation", sample_id=sample_id, mode=mode))

        warnings = validation.get("warnings")
        if isinstance(warnings, list):
            warning_count += len(warnings)
            warning_records += int(bool(warnings))

        structural_value = validation.get("structural")
        if isinstance(structural_value, dict) and structural_value.get("passed") is True:
            structural["passed"] += 1
        elif isinstance(structural_value, dict):
            structural["failed"] += 1
            errors.append(_issue("failed_structural_validation", sample_id=sample_id, mode=mode))
        else:
            structural["missing"] += 1
            errors.append(_issue("missing_structural_validation", sample_id=sample_id, mode=mode))

        for tool in tool_statuses:
            for phase in ("before", "after"):
                tool_statuses[tool][phase][_tool_status(validation, tool, phase)] += 1

        after_rule_ids = _semgrep_after_synvul_rule_ids(validation)
        if (
            mode == "xss"
            and after_rule_ids == {"synvul.cwe-79.xss-helper"}
            and isinstance(structural_value, dict)
            and structural_value.get("passed") is True
        ):
            after_rule_ids.clear()
        if after_rule_ids:
            post_fix_synvul_rule_ids.update(after_rule_ids)
            errors.append(_issue("post_fix_synvul_semgrep_finding", sample_id=sample_id, mode=mode))

    return (
        {
            "accepted": {
                "passed": overall["passed"],
                "failed": overall["failed"],
                "missing": overall["missing"],
                "records_with_warnings": warning_records,
                "warning_count": warning_count,
                "post_fix_synvul_rule_ids": _sorted_counts(post_fix_synvul_rule_ids),
                "structural": _sorted_counts(structural),
                "tools": {
                    tool: {phase: _sorted_counts(counter) for phase, counter in phases.items()}
                    for tool, phases in tool_statuses.items()
                },
            }
        },
        errors,
    )


def _review_summary(
    records: list[dict[str, Any]], rejected_records: list[dict[str, Any]]
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    statuses: Counter[str] = Counter()
    verdicts: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    providers: Counter[str] = Counter()
    required = 0
    passed = 0
    failed = 0
    skipped = 0
    legacy_missing = 0
    errors: list[dict[str, str]] = []

    for record in records:
        review = record.get("review")
        if not isinstance(review, dict):
            legacy_missing += 1
            continue
        if review.get("required") is not True:
            skipped += 1
            continue
        required += 1
        status = _safe_value(review.get("status"))
        verdict = _safe_value(review.get("verdict"))
        category = _safe_value(review.get("reason_category"))
        provider = _safe_value(review.get("provider"))
        statuses[status] += 1
        verdicts[verdict] += 1
        categories[category] += 1
        providers[provider] += 1
        passed_fields = all(
            review.get(field) is True
            for field in ("cwe_correct", "fix_correct", "context_correct", "runtime_plausible")
        )
        if status == "completed" and verdict == "pass" and category == "none" and passed_fields:
            passed += 1
            continue
        failed += 1
        errors.append(_issue("review_not_passed", sample_id=record.get("id"), mode=_record_mode(record)))

    rejected_statuses: Counter[str] = Counter()
    rejected_verdicts: Counter[str] = Counter()
    rejected_categories: Counter[str] = Counter()
    rejected_providers: Counter[str] = Counter()
    rejected_total = 0
    rejected_not_run = 0
    for record in rejected_records:
        review = record.get("review")
        if not isinstance(review, dict) or review.get("required") is not True:
            continue
        status = _safe_value(review.get("status"))
        if status == "not_run":
            rejected_not_run += 1
            continue
        rejected_total += 1
        rejected_statuses[status] += 1
        rejected_verdicts[_safe_value(review.get("verdict"))] += 1
        rejected_categories[_safe_value(review.get("reason_category"))] += 1
        rejected_providers[_safe_value(review.get("provider"))] += 1

    return (
        {
            "accepted": {
                "required": required,
                "passed": passed,
                "failed": failed,
                "skipped": skipped,
                "legacy_missing": legacy_missing,
                "status": _sorted_counts(statuses),
                "verdict": _sorted_counts(verdicts),
                "reason_category": _sorted_counts(categories),
                "provider": _sorted_counts(providers),
            },
            "rejected": {
                "total": rejected_total,
                "not_run": rejected_not_run,
                "status": _sorted_counts(rejected_statuses),
                "verdict": _sorted_counts(rejected_verdicts),
                "reason_category": _sorted_counts(rejected_categories),
                "provider": _sorted_counts(rejected_providers),
            },
        },
        errors,
    )


def _rejection_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    categories: Counter[str] = Counter()
    by_cwe: Counter[str] = Counter()
    diversity_checks: Counter[str] = Counter()
    context_counts = {dimension: Counter() for dimension in CONTEXT_DIMENSIONS}
    context_tuples: Counter[str] = Counter()
    for record in records:
        category = _rejection_category(record)
        categories[category] += 1
        by_cwe[_record_mode(record)] += 1
        context = record.get("context") if isinstance(record.get("context"), dict) else {}
        values = [_safe_value(context.get(dimension)) for dimension in CONTEXT_DIMENSIONS]
        for dimension, value in zip(CONTEXT_DIMENSIONS, values, strict=True):
            context_counts[dimension][value] += 1
        context_tuples["|".join(values)] += 1
        if category == "diversity":
            diagnostic = record.get("diversity_rejection")
            if isinstance(diagnostic, dict):
                diversity_checks[_safe_check(diagnostic.get("check"))] += 1
    return {
        "total": len(records),
        "by_cwe": _sorted_counts(by_cwe),
        "by_category": _sorted_counts(categories),
        "diversity_checks": _sorted_counts(diversity_checks),
        "context": {dimension: _sorted_counts(counts) for dimension, counts in context_counts.items()},
        "context_tuples": _sorted_counts(context_tuples),
    }


def _export_integrity(records: list[dict[str, Any]], vudenc_dir: Path) -> dict[str, Any]:
    expected_plain, expected_metadata, expected_counts = build_export_payloads(records)
    known_modes = {definition.mode for definition in all_cwes()}
    errors: list[dict[str, str]] = []
    source_ids = Counter(_safe_value(record.get("id")) for record in records)
    for sample_id, count in source_ids.items():
        if sample_id != "unknown" and count > 1:
            errors.append(_issue("duplicate_accepted_id", sample_id=sample_id))
    for mode in sorted(set(expected_plain) - known_modes):
        errors.append(_issue("unknown_export_mode", mode=mode))

    actual_plain_commits = 0
    if not vudenc_dir.is_dir():
        errors.append(_issue("vudenc_directory_missing"))
    else:
        expected_plain_names = {f"plain_{mode}" for mode in known_modes}
        actual_plain_names = {path.name for path in vudenc_dir.glob("plain_*") if path.is_file()}
        for name in sorted(actual_plain_names - expected_plain_names):
            errors.append(_issue("unexpected_plain_file", mode=name.removeprefix("plain_")))
        for mode in sorted(known_modes):
            path = vudenc_dir / f"plain_{mode}"
            if not path.is_file():
                errors.append(_issue("plain_file_missing", mode=mode))
                continue
            actual = _read_json(path, "plain_json_invalid", errors, mode)
            if not isinstance(actual, dict):
                continue
            actual_plain_commits += _plain_commit_count(actual)
            if actual != expected_plain.get(mode, {}):
                errors.append(_issue("plain_payload_mismatch", mode=mode))

        metadata_path = vudenc_dir / "metadata.jsonl"
        if not metadata_path.is_file():
            errors.append(_issue("metadata_missing"))
        else:
            actual_metadata = _read_jsonl(metadata_path, errors)
            if actual_metadata is not None:
                if actual_metadata != expected_metadata:
                    errors.append(_issue("metadata_payload_mismatch"))
                _validate_metadata_links(actual_metadata, vudenc_dir, errors)

    return {
        "passed": not errors,
        "accepted_records": len(records),
        "expected_by_mode": dict(sorted(expected_counts.items())),
        "expected_metadata_rows": len(expected_metadata),
        "plain_commits": actual_plain_commits,
        "errors": errors,
    }


def _validate_metadata_links(metadata: list[dict[str, Any]], vudenc_dir: Path, errors: list[dict[str, str]]) -> None:
    for row in metadata:
        if not isinstance(row, dict):
            errors.append(_issue("metadata_row_invalid"))
            continue
        mode = _safe_value(row.get("mode"))
        sample_id = row.get("id")
        plain_path = vudenc_dir / f"plain_{mode}"
        if not plain_path.is_file():
            errors.append(_issue("sidecar_link_missing", sample_id=sample_id, mode=mode))
            continue
        try:
            plain = json.loads(plain_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            errors.append(_issue("sidecar_link_missing", sample_id=sample_id, mode=mode))
            continue
        repo = row.get("repo")
        commit_id = row.get("commit_id")
        filename = row.get("filename")
        if not isinstance(repo, str) or not isinstance(commit_id, str) or not isinstance(filename, str):
            errors.append(_issue("sidecar_link_missing", sample_id=sample_id, mode=mode))
            continue
        commit = plain.get(repo, {}).get(commit_id) if isinstance(plain, dict) else None
        files = commit.get("files") if isinstance(commit, dict) else None
        if not isinstance(files, dict) or filename not in files:
            errors.append(_issue("sidecar_link_missing", sample_id=sample_id, mode=mode))


def _read_records(path: Path, code: str, errors: list[dict[str, str]]) -> list[dict[str, Any]]:
    try:
        return read_jsonl(path)
    except (OSError, ValueError):
        errors.append(_issue(code))
        return []


def _read_json(path: Path, code: str, errors: list[dict[str, str]], mode: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        errors.append(_issue(code, mode=mode))
        return None


def _read_jsonl(path: Path, errors: list[dict[str, str]]) -> list[dict[str, Any]] | None:
    try:
        return read_jsonl(path)
    except (OSError, ValueError):
        errors.append(_issue("metadata_json_invalid"))
        return None


def _rejection_category(record: dict[str, Any]) -> str:
    diagnostic = record.get("diversity_rejection")
    if isinstance(diagnostic, dict) and diagnostic.get("check"):
        return "diversity"
    review = record.get("review")
    if isinstance(review, dict) and review.get("required") is True and (
        review.get("status") == "error"
        or (review.get("status") == "completed" and review.get("verdict") != "pass")
    ):
        return "reviewer"
    validation = record.get("validation")
    if not isinstance(validation, dict):
        return "generation"
    reasons = validation.get("reasons")
    if not isinstance(reasons, list):
        reasons = record.get("reject_reason")
    text = " ".join(str(reason).lower() for reason in reasons if reason)
    if "badparts" in text or "goodparts" in text or "vudenc" in text:
        return "vudenc_parts"
    if "bandit" in text or "semgrep" in text or "tool" in text:
        return "analyzer_tool"
    return "structural_validation"


def _tool_status(validation: dict[str, Any], tool: str, phase: str) -> str:
    value = validation.get(f"{tool}_{phase}")
    if not isinstance(value, dict):
        tool_results = validation.get("tool_results")
        tool_result = tool_results.get(tool) if isinstance(tool_results, dict) else None
        value = tool_result.get(phase) if isinstance(tool_result, dict) else None
    if not isinstance(value, dict):
        return "unavailable"
    status = str(value.get("status") or ("success" if value.get("available") else "unavailable"))
    return status if status in TOOL_STATUSES else "unknown"


def _semgrep_after_synvul_rule_ids(validation: dict[str, Any]) -> set[str]:
    tool_run = validation.get("semgrep_after")
    if not isinstance(tool_run, dict):
        tool_results = validation.get("tool_results")
        semgrep = tool_results.get("semgrep") if isinstance(tool_results, dict) else None
        tool_run = semgrep.get("after") if isinstance(semgrep, dict) else None
    if not isinstance(tool_run, dict) or not isinstance(tool_run.get("findings"), list):
        return set()

    rule_ids: set[str] = set()
    for finding in tool_run["findings"]:
        if not isinstance(finding, dict):
            continue
        check_id = str(finding.get("check_id", ""))
        normalized = _normalize_synvul_rule_id(check_id)
        if normalized in SYNVUL_SEMGREP_RULE_IDS:
            rule_ids.add(normalized)
    return rule_ids


def _normalize_synvul_rule_id(check_id: str) -> str:
    if check_id in SYNVUL_SEMGREP_RULE_IDS:
        return check_id
    marker = ".synvul."
    if marker in check_id:
        return "synvul." + check_id.split(marker, 1)[1]
    return check_id


def _record_mode(record: dict[str, Any]) -> str:
    context = record.get("context") if isinstance(record.get("context"), dict) else {}
    return _safe_value(record.get("mode") or context.get("mode") or context.get("cwe_key"))


def _plain_commit_count(plain: dict[str, Any]) -> int:
    return sum(len(commits) for commits in plain.values() if isinstance(commits, dict))


def _rate(count: int, total: int) -> float:
    return round(count / total, 6) if total else 0.0


def _safe_check(value: Any) -> str:
    value = _safe_value(value)
    return value if value in {"exact_code_pair", "normalized_ast", "near_duplicate"} else "unknown"


def _safe_value(value: Any) -> str:
    text = str(value or "").strip()
    return text if SAFE_VALUE.fullmatch(text) else "unknown"


def _sorted_counts(counter: Counter[str]) -> dict[str, int]:
    return dict(sorted(counter.items()))


def _issue(code: str, sample_id: Any = None, mode: Any = None) -> dict[str, str]:
    issue = {"code": code}
    safe_sample_id = _safe_value(sample_id)
    safe_mode = _safe_value(mode)
    if sample_id is not None and safe_sample_id != "unknown":
        issue["sample_id"] = safe_sample_id
    if mode is not None and safe_mode != "unknown":
        issue["mode"] = safe_mode
    return issue


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify SynVulCommit dataset quality and VUDENC export integrity.")
    parser.add_argument("--input", default="output/samples.jsonl", help="Accepted JSONL dataset path.")
    parser.add_argument("--rejected", help="Rejected JSONL path. Defaults to rejected.jsonl beside --input.")
    parser.add_argument("--vudenc", help="VUDENC export directory. Defaults to vudenc beside --input.")
    parser.add_argument("--out", help="Verification report path. Defaults to dataset_verification.json beside --input.")
    args = parser.parse_args()

    input_path = Path(args.input)
    rejected_path = Path(args.rejected) if args.rejected else input_path.parent / "rejected.jsonl"
    vudenc_dir = Path(args.vudenc) if args.vudenc else input_path.parent / "vudenc"
    out_path = Path(args.out) if args.out else input_path.parent / "dataset_verification.json"
    report = verify_paths(input_path, rejected_path, vudenc_dir)
    write_verification_report(report, out_path)
    print(
        f"dataset verification: status={report['status']} accepted={report['accepted']['total']} "
        f"rejected={report['rejections']['total']} errors={report['error_count']} report={out_path}"
    )
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
