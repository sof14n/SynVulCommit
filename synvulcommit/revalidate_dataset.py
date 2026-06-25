from __future__ import annotations

import argparse
import json
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .cwe_registry import get_cwe
from .export_vudenc import export_records
from .llm_generator import GeneratedCommit
from .spec_sampler import GenerationSpec
from .storage import append_jsonl, ensure_output_files, read_jsonl
from .validator import validate_candidate
from .verify_dataset import verify_dataset, write_verification_report


def revalidate_output(source_dir: Path, output_dir: Path, require_tools: bool = False, workers: int = 10) -> dict[str, Any]:
    if workers < 1:
        raise ValueError("workers must be at least 1")
    if source_dir.resolve() == output_dir.resolve():
        raise ValueError("source and output directories must be different")
    samples_path = source_dir / "samples.jsonl"
    if not samples_path.is_file():
        raise ValueError(f"accepted input is missing: {samples_path}")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError(f"output directory must be empty: {output_dir}")

    source_records = read_jsonl(samples_path)
    output_samples, output_rejected = ensure_output_files(output_dir)
    rules_dir = Path(__file__).resolve().parent / "rules"
    temp_root = output_dir / "tmp"

    worker_count = min(workers, max(1, len(source_records)))
    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="synvul-revalidate") as executor:
        results = list(
            executor.map(
                lambda record: _revalidate_record(record, rules_dir, temp_root, require_tools),
                source_records,
            )
        )

    retained: list[dict[str, Any]] = []
    quarantined: list[dict[str, Any]] = []
    retained_by_mode: Counter[str] = Counter()
    quarantined_by_mode: Counter[str] = Counter()
    quarantine_categories: Counter[str] = Counter()
    for record, is_valid, categories in results:
        mode = _record_mode(record)
        if is_valid:
            append_jsonl(output_samples, record)
            retained.append(record)
            retained_by_mode[mode] += 1
            continue

        record["revalidation"] = {
            "source_id": str(record.get("id") or "unknown"),
            "status": "quarantined",
            "reason_categories": sorted(categories),
        }
        append_jsonl(output_rejected, record)
        quarantined.append(record)
        quarantined_by_mode[mode] += 1
        quarantine_categories.update(categories)

    vudenc_dir = output_dir / "vudenc"
    export_records(retained, vudenc_dir)
    verification = verify_dataset(retained, quarantined, vudenc_dir)
    write_verification_report(verification, output_dir / "dataset_verification.json")
    summary = {
        "schema_version": 1,
        "source_accepted": len(source_records),
        "retained": len(retained),
        "quarantined": len(quarantined),
        "retained_by_mode": dict(sorted(retained_by_mode.items())),
        "quarantined_by_mode": dict(sorted(quarantined_by_mode.items())),
        "quarantine_reason_categories": dict(sorted(quarantine_categories.items())),
        "verification_status": verification["status"],
        "verification_error_count": verification["error_count"],
    }
    (output_dir / "revalidation_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def _revalidate_record(
    source_record: dict[str, Any], rules_dir: Path, temp_root: Path, require_tools: bool
) -> tuple[dict[str, Any], bool, set[str]]:
    record = dict(source_record)
    try:
        spec = _spec_from_record(record)
        candidate = _candidate_from_record(record)
        validation = validate_candidate(spec, candidate, rules_dir, temp_root, require_tools)
        validation_data = validation.to_dict()
        reasons = list(validation_data["reasons"])
    except (KeyError, TypeError, ValueError):
        validation_data = _invalid_validation()
        reasons = ["revalidation record could not be reconstructed"]

    if not _has_passing_review(record):
        reasons.append("revalidation requires an existing passing reviewer verdict")
    validation_data["reasons"] = reasons
    validation_data["passed"] = not reasons
    record["validation"] = validation_data
    if not reasons:
        return record, True, set()

    record["reject_reason"] = reasons
    return record, False, {_reason_category(reason) for reason in reasons}


def _spec_from_record(record: dict[str, Any]) -> GenerationSpec:
    context = record.get("context")
    if not isinstance(context, dict):
        raise ValueError("record context is missing")
    definition = get_cwe(str(context.get("cwe_key") or record.get("mode") or ""))
    return GenerationSpec(
        cwe_key=definition.key,
        cwe=str(record.get("cwe") or definition.cwe),
        cwe_name=str(record.get("cwe_name") or definition.name),
        mode=definition.mode,
        application_type=str(context["application_type"]),
        flow_pattern=str(context["flow_pattern"]),
        difficulty=str(context["difficulty"]),
        structure=str(context["structure"]),
        sample_index=int(context["sample_index"]),
    )


def _candidate_from_record(record: dict[str, Any]) -> GeneratedCommit:
    return GeneratedCommit(
        commit_message=str(record.get("commit_message") or "Synthetic security fix"),
        filename=str(record.get("filename") or "app.py"),
        vulnerable_code=str(record["vulnerable_code"]),
        fixed_code=str(record["fixed_code"]),
        diff=str(record.get("diff") or ""),
        badparts=[str(item) for item in record.get("badparts", [])],
        goodparts=[str(item) for item in record.get("goodparts", [])],
        provider=str(record.get("provider") or "unknown"),
        raw_response={},
    )


def _has_passing_review(record: dict[str, Any]) -> bool:
    review = record.get("review")
    if not isinstance(review, dict):
        return False
    return (
        review.get("required") is True
        and review.get("status") == "completed"
        and review.get("verdict") == "pass"
        and review.get("reason_category") == "none"
        and all(review.get(field) is True for field in ("cwe_correct", "fix_correct", "context_correct", "runtime_plausible"))
    )


def _invalid_validation() -> dict[str, Any]:
    return {
        "passed": False,
        "reasons": [],
        "warnings": [],
        "structural": {"passed": False, "vulnerable_markers": [], "fixed_markers": []},
        "bandit_before": {"available": False, "status": "unavailable", "findings": []},
        "bandit_after": {"available": False, "status": "unavailable", "findings": []},
        "semgrep_before": {"available": False, "status": "unavailable", "findings": []},
        "semgrep_after": {"available": False, "status": "unavailable", "findings": []},
    }


def _reason_category(reason: str) -> str:
    lowered = reason.lower()
    if "other synvulcommit rule ids" in lowered or "semgrep still reports" in lowered:
        return "post_fix_semgrep"
    if "path-safe containment" in lowered:
        return "path_containment"
    if "reviewer" in lowered:
        return "review"
    if "could not be reconstructed" in lowered:
        return "record_schema"
    return "validation"


def _record_mode(record: dict[str, Any]) -> str:
    context = record.get("context")
    if isinstance(context, dict) and context.get("mode"):
        return str(context["mode"])
    return str(record.get("mode") or "unknown")


def main() -> int:
    parser = argparse.ArgumentParser(description="Revalidate accepted SynVulCommit records into a clean output directory.")
    parser.add_argument("--input", required=True, help="Source output directory containing samples.jsonl.")
    parser.add_argument("--output", required=True, help="New empty output directory for retained and quarantined records.")
    parser.add_argument("--require-tools", action="store_true", help="Reject records when Bandit or Semgrep is unavailable.")
    parser.add_argument("--workers", type=int, default=10, help="Concurrent local validation workers.")
    args = parser.parse_args()
    try:
        summary = revalidate_output(Path(args.input), Path(args.output), args.require_tools, args.workers)
    except ValueError as exc:
        parser.error(str(exc))
    print(
        f"revalidation: retained={summary['retained']} quarantined={summary['quarantined']} "
        f"verification={summary['verification_status']} output={args.output}"
    )
    return 0 if summary["verification_status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
