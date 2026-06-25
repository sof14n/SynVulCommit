from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from time import perf_counter
from typing import Any

from .diversity import DiversityIndex, write_diversity_summary
from .export_vudenc import export_records
from .llm_generator import GenerationError, generate_commit, validate_provider_configuration
from .prompt_builder import build_prompt
from .reviewer import review_candidate, review_error, review_not_run, validate_reviewer_configuration
from .spec_sampler import CoveragePlan, GenerationSpec, build_coverage_plan
from .storage import append_jsonl, ensure_output_files, next_sample_id, read_jsonl
from .validator import validate_candidate
from .verify_dataset import verify_paths, write_verification_report


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate validated synthetic Python vulnerability-fix commits.")
    parser.add_argument(
        "--per-cwe",
        type=int,
        default=1,
        help="Target accepted count per CWE, including accepted records already in --output.",
    )
    parser.add_argument("--provider", default="mock", choices=("mock", "openai_compatible", "local_http"))
    parser.add_argument("--output", default="output", help="Output directory.")
    parser.add_argument("--seed", type=int, default=1337, help="Random seed for task sampling.")
    parser.add_argument("--max-attempts", type=int, default=5, help="Generation attempts per requested spec.")
    parser.add_argument(
        "--workers",
        type=int,
        default=10,
        help="Maximum concurrent generation-and-validation pipelines. Use 1 for serial execution.",
    )
    parser.add_argument("--cwe", action="append", help="Limit generation to one or more CWE keys/modes, e.g. --cwe xsrf --cwe sql.")
    parser.add_argument("--require-tools", action="store_true", help="Fail validation if Bandit or Semgrep is missing.")
    parser.add_argument("--no-review", action="store_true", help="Skip the required LLM reviewer for diagnostic runs.")
    parser.add_argument(
        "--review-provider",
        choices=("mock", "openai_compatible", "local_http"),
        help="Reviewer provider. Defaults to the generation provider and configuration.",
    )
    parser.add_argument("--no-export", action="store_true", help="Do not export VUDENC-style files after generation.")
    args = parser.parse_args()
    if args.max_attempts < 1:
        parser.error("--max-attempts must be at least 1")
    if args.workers < 1:
        parser.error("--workers must be at least 1")

    try:
        validate_provider_configuration(args.provider)
        if not args.no_review:
            validate_provider_configuration(
                args.review_provider or args.provider,
                reviewer_profile=args.review_provider is not None,
            )
            validate_reviewer_configuration()
    except GenerationError as exc:
        print(f"configuration error: {exc}")
        return 2

    output_dir = Path(args.output)
    samples_path, rejected_path = ensure_output_files(output_dir)
    existing_records = read_jsonl(samples_path)
    diversity = DiversityIndex()
    diversity.load_existing(existing_records)

    rules_dir = Path(__file__).resolve().parent / "rules"
    temp_root = output_dir / "tmp"

    try:
        coverage_plan = build_coverage_plan(
            per_cwe=args.per_cwe,
            seed=args.seed,
            existing_records=existing_records,
            cwe_filters=args.cwe,
        )
    except ValueError as exc:
        parser.error(str(exc))
    if not coverage_plan.matched:
        print(f"no specs matched --cwe values: {', '.join(args.cwe or [])}")
        return 2

    worker_count = min(args.workers, len(coverage_plan.specs))
    state = _GenerationState(
        existing_records=existing_records,
        diversity=diversity,
        coverage_plan=coverage_plan,
        samples_path=samples_path,
        rejected_path=rejected_path,
        provider=args.provider,
        review_provider=args.review_provider or args.provider,
        reviewer_profile=args.review_provider is not None,
        review_enabled=not args.no_review,
        workers=worker_count,
    )
    if coverage_plan.specs:
        with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="synvulcommit") as executor:
            futures = [
                executor.submit(
                    _generate_for_spec,
                    spec,
                    args.max_attempts,
                    args.require_tools,
                    rules_dir,
                    temp_root,
                    state,
                )
                for spec in coverage_plan.specs
            ]
            for future in as_completed(futures):
                future.result()

    accepted, rejected = state.counts()

    diversity_summary = diversity.summary()
    diversity_summary["coverage"] = coverage_plan.summary()
    diversity_summary["performance"] = state.performance_summary()
    diversity_summary["review"] = state.review_summary()
    diversity_summary_path = output_dir / "diversity_summary.json"
    write_diversity_summary(diversity_summary, diversity_summary_path)
    _print_coverage_status(coverage_plan)
    print(f"wrote diversity summary to {diversity_summary_path}")
    _print_performance(state.performance_summary())

    verification_failed = False
    if not args.no_export:
        vudenc_dir = output_dir / "vudenc"
        counts = export_records(read_jsonl(samples_path), vudenc_dir)
        for mode, count in counts.items():
            print(f"exported {count:4d} samples to plain_{mode}")
        verification_path = output_dir / "dataset_verification.json"
        verification = verify_paths(samples_path, rejected_path, vudenc_dir)
        write_verification_report(verification, verification_path)
        verification_failed = verification["status"] != "pass"
        print(
            f"dataset verification: status={verification['status']} errors={verification['error_count']} "
            f"report={verification_path}"
        )

    print(f"done: accepted={accepted}, rejected={rejected}, samples={samples_path}, rejected_log={rejected_path}")
    return 1 if coverage_plan.has_unfilled or verification_failed else 0


@dataclass
class _GenerationState:
    existing_records: list[dict[str, Any]]
    diversity: DiversityIndex
    coverage_plan: CoveragePlan
    samples_path: Path
    rejected_path: Path
    provider: str
    review_provider: str
    reviewer_profile: bool
    review_enabled: bool
    workers: int
    lock: Lock = field(default_factory=Lock)
    started_at: float = field(default_factory=perf_counter)
    accepted: int = 0
    rejected: int = 0
    attempts: int = 0
    provider_seconds: float = 0.0
    validation_seconds: float = 0.0
    review_seconds: float = 0.0
    review_passed: int = 0
    review_rejected: int = 0
    review_errors: int = 0

    def record_generation_error(self, spec: GenerationSpec, attempt: int, error: GenerationError, elapsed: float) -> None:
        with self.lock:
            self.attempts += 1
            self.rejected += 1
            self.provider_seconds += elapsed
            append_jsonl(
                self.rejected_path,
                {
                    "context": spec.to_dict(),
                    "attempt": attempt,
                    "provider": self.provider,
                    "review": review_not_run(self.review_enabled),
                    "reject_reason": [str(error)],
                },
            )
            self.coverage_plan.mark_rejected_attempt(spec)

    def record_candidate(
        self,
        spec: GenerationSpec,
        candidate: Any,
        validation: Any,
        attempt: int,
        provider_seconds: float,
        validation_seconds: float,
        review: dict[str, Any] | None = None,
        review_seconds: float = 0.0,
    ) -> bool:
        with self.lock:
            if review is None:
                review = review_not_run(self.review_enabled)
            self.attempts += 1
            self.provider_seconds += provider_seconds
            self.validation_seconds += validation_seconds
            self.review_seconds += review_seconds
            record = _build_record(
                sample_id=next_sample_id(self.existing_records, spec.cwe, spec.mode),
                spec=spec,
                candidate=candidate,
                validation=validation.to_dict(),
                attempt=attempt,
                review=review,
            )
            if not validation.passed:
                append_jsonl(self.rejected_path, {**record, "reject_reason": validation.reasons})
                self.rejected += 1
                self.coverage_plan.mark_rejected_attempt(spec)
                return False

            diverse, reason = self.diversity.accepts(record)
            if not diverse:
                append_jsonl(
                    self.rejected_path,
                    {
                        **record,
                        "reject_reason": [reason],
                        "diversity_rejection": self.diversity.last_rejection or {},
                    },
                )
                self.rejected += 1
                self.coverage_plan.mark_rejected_attempt(spec)
                return False

            append_jsonl(self.samples_path, record)
            self.existing_records.append(record)
            self.accepted += 1
            if review.get("status") == "completed" and review.get("verdict") == "pass":
                self.review_passed += 1
            self.coverage_plan.mark_accepted(spec)
            print(f"accepted {record['id']} ({spec.cwe} {spec.mode})")
            return True

    def record_review_rejection(
        self,
        spec: GenerationSpec,
        candidate: Any,
        validation: Any,
        attempt: int,
        provider_seconds: float,
        validation_seconds: float,
        review: dict[str, Any],
        review_seconds: float,
        reason: str,
        review_error: bool = False,
    ) -> None:
        with self.lock:
            self.attempts += 1
            self.rejected += 1
            self.provider_seconds += provider_seconds
            self.validation_seconds += validation_seconds
            self.review_seconds += review_seconds
            if review_error:
                self.review_errors += 1
            else:
                self.review_rejected += 1
            record = _build_record(
                sample_id=next_sample_id(self.existing_records, spec.cwe, spec.mode),
                spec=spec,
                candidate=candidate,
                validation=validation.to_dict(),
                attempt=attempt,
                review=review,
            )
            append_jsonl(self.rejected_path, {**record, "reject_reason": [reason]})
            self.coverage_plan.mark_rejected_attempt(spec)

    def mark_unfilled(self, spec: GenerationSpec, max_attempts: int) -> None:
        with self.lock:
            self.coverage_plan.mark_unfilled(spec)
            print(f"failed to accept {spec.cwe} {spec.mode} after {max_attempts} attempts")

    def counts(self) -> tuple[int, int]:
        with self.lock:
            return self.accepted, self.rejected

    def performance_summary(self) -> dict[str, int | float]:
        with self.lock:
            elapsed = max(perf_counter() - self.started_at, 0.001)
            return {
                "workers": self.workers,
                "attempts": self.attempts,
                "accepted": self.accepted,
                "rejected": self.rejected,
                "elapsed_seconds": round(elapsed, 3),
                "accepted_per_minute": round(self.accepted * 60 / elapsed, 3),
                "attempts_per_minute": round(self.attempts * 60 / elapsed, 3),
                "provider_work_seconds": round(self.provider_seconds, 3),
                "validation_work_seconds": round(self.validation_seconds, 3),
                "review_work_seconds": round(self.review_seconds, 3),
            }

    def review_summary(self) -> dict[str, int | bool]:
        with self.lock:
            return {
                "enabled": self.review_enabled,
                "passed": self.review_passed,
                "rejected": self.review_rejected,
                "errors": self.review_errors,
            }


def _generate_for_spec(
    spec: GenerationSpec,
    max_attempts: int,
    require_tools: bool,
    rules_dir: Path,
    temp_root: Path,
    state: _GenerationState,
) -> None:
    for attempt in range(1, max_attempts + 1):
        prompt = build_prompt(spec)
        started = perf_counter()
        try:
            candidate = generate_commit(state.provider, spec, prompt)
        except GenerationError as exc:
            state.record_generation_error(spec, attempt, exc, perf_counter() - started)
            continue

        provider_seconds = perf_counter() - started
        validation_started = perf_counter()
        validation = validate_candidate(
            spec=spec,
            candidate=candidate,
            rules_dir=rules_dir,
            temp_root=temp_root,
            require_tools=require_tools,
        )
        validation_seconds = perf_counter() - validation_started
        if not validation.passed:
            state.record_candidate(
                spec=spec,
                candidate=candidate,
                validation=validation,
                attempt=attempt,
                provider_seconds=provider_seconds,
                validation_seconds=validation_seconds,
            )
            continue

        review: dict[str, Any] | None = None
        review_seconds = 0.0
        if state.review_enabled:
            review_started = perf_counter()
            try:
                result = review_candidate(
                    state.review_provider,
                    spec,
                    candidate,
                    reviewer_profile=state.reviewer_profile,
                )
            except GenerationError:
                review_seconds = perf_counter() - review_started
                state.record_review_rejection(
                    spec=spec,
                    candidate=candidate,
                    validation=validation,
                    attempt=attempt,
                    provider_seconds=provider_seconds,
                    validation_seconds=validation_seconds,
                    review=review_error(state.review_provider, state.reviewer_profile),
                    review_seconds=review_seconds,
                    reason="reviewer provider failed",
                    review_error=True,
                )
                continue
            review_seconds = perf_counter() - review_started
            review = result.to_dict()
            if not result.passed:
                state.record_review_rejection(
                    spec=spec,
                    candidate=candidate,
                    validation=validation,
                    attempt=attempt,
                    provider_seconds=provider_seconds,
                    validation_seconds=validation_seconds,
                    review=review,
                    review_seconds=review_seconds,
                    reason=f"reviewer rejected candidate: {result.verdict}/{result.reason_category}",
                )
                continue

        accepted = state.record_candidate(
            spec=spec,
            candidate=candidate,
            validation=validation,
            attempt=attempt,
            provider_seconds=provider_seconds,
            validation_seconds=validation_seconds,
            review=review,
            review_seconds=review_seconds,
        )
        if accepted:
            return

    state.mark_unfilled(spec, max_attempts)


def _build_record(
    sample_id: str,
    spec: GenerationSpec,
    candidate: Any,
    validation: dict[str, Any],
    attempt: int,
    review: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record = {
        "id": sample_id,
        "cwe": spec.cwe,
        "cwe_name": spec.cwe_name,
        "mode": spec.mode,
        "context": spec.to_dict(),
        "attempt": attempt,
        "commit_message": candidate.commit_message,
        "filename": candidate.filename,
        "vulnerable_code": candidate.vulnerable_code,
        "fixed_code": candidate.fixed_code,
        "diff": candidate.diff,
        "badparts": candidate.badparts,
        "goodparts": candidate.goodparts,
        "provider": candidate.provider,
        "validation": validation,
    }
    if review is not None:
        record["review"] = review
    return record


def _print_coverage_status(coverage_plan: CoveragePlan) -> None:
    print("coverage summary:")
    for mode, item in coverage_plan.summary().items():
        print(
            f"  {item['cwe']} {mode}: target={item['target_accepted']} existing={item['existing_accepted']} "
            f"planned={item['planned']} accepted={item['accepted']} total={item['total_accepted']} "
            f"rejected={item['rejected']} unfilled={item['unfilled']}"
        )


def _print_performance(performance: dict[str, int | float]) -> None:
    print(
        "performance: "
        f"workers={performance['workers']} elapsed={performance['elapsed_seconds']}s "
        f"attempts/min={performance['attempts_per_minute']} accepted/min={performance['accepted_per_minute']} "
        f"provider_work={performance['provider_work_seconds']}s "
        f"validation_work={performance['validation_work_seconds']}s "
        f"review_work={performance['review_work_seconds']}s"
    )


if __name__ == "__main__":
    raise SystemExit(main())
