from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from .diversity import DiversityIndex
from .export_vudenc import export_records
from .llm_generator import GenerationError, generate_commit, provider_model_name
from .prompt_builder import build_prompt
from .spec_sampler import GenerationSpec, iter_specs
from .storage import append_jsonl, ensure_output_files, next_sample_id, read_jsonl
from .validator import validate_candidate


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate validated synthetic Python vulnerability-fix commits.")
    parser.add_argument("--per-cwe", type=int, default=1, help="Accepted samples to generate per CWE.")
    parser.add_argument("--provider", default="mock", choices=("mock", "openai_compatible", "local_http"))
    parser.add_argument("--output", default="output", help="Output directory.")
    parser.add_argument("--seed", type=int, default=1337, help="Random seed for task sampling.")
    parser.add_argument("--max-attempts", type=int, default=5, help="Generation attempts per requested spec.")
    parser.add_argument("--cwe", action="append", help="Limit generation to one or more CWE keys/modes, e.g. --cwe xsrf --cwe sql.")
    parser.add_argument("--require-tools", action="store_true", help="Fail validation if Bandit or Semgrep is missing.")
    parser.add_argument("--no-export", action="store_true", help="Do not export VUDENC-style files after generation.")
    args = parser.parse_args()

    output_dir = Path(args.output)
    samples_path, rejected_path = ensure_output_files(output_dir)
    existing_records = read_jsonl(samples_path)
    diversity = DiversityIndex()
    diversity.load_existing(existing_records)

    rules_dir = Path(__file__).resolve().parent / "rules"
    temp_root = output_dir / "tmp"

    accepted = 0
    rejected = 0
    specs = iter_specs(args.per_cwe, seed=args.seed)
    if args.cwe:
        wanted = {value.lower().strip() for value in args.cwe}
        specs = [spec for spec in specs if spec.cwe_key in wanted or spec.mode in wanted or spec.cwe.lower() in wanted]
        if not specs:
            print(f"no specs matched --cwe values: {', '.join(args.cwe)}")
            return 2
    for spec in specs:
        accepted_for_spec = False
        for attempt in range(1, args.max_attempts + 1):
            prompt = build_prompt(spec)
            try:
                candidate = generate_commit(args.provider, spec, prompt)
                validation = validate_candidate(
                    spec=spec,
                    candidate=candidate,
                    rules_dir=rules_dir,
                    temp_root=temp_root,
                    require_tools=args.require_tools,
                )
                record = _build_record(
                    sample_id=next_sample_id(existing_records, spec.cwe, spec.mode),
                    spec=spec,
                    candidate=candidate,
                    validation=validation.to_dict(),
                    attempt=attempt,
                )

                if not validation.passed:
                    append_jsonl(rejected_path, {**record, "reject_reason": validation.reasons})
                    rejected += 1
                    continue

                diverse, reason = diversity.accepts(record)
                if not diverse:
                    append_jsonl(rejected_path, {**record, "reject_reason": [reason]})
                    rejected += 1
                    continue

                append_jsonl(samples_path, record)
                existing_records.append(record)
                accepted += 1
                accepted_for_spec = True
                print(f"accepted {record['id']} ({spec.cwe} {spec.mode})")
                break
            except GenerationError as exc:
                model = provider_model_name(args.provider)
                reason = getattr(exc, "reason", "generation_error")
                print(
                    f"rejected generation provider={args.provider} model={model} "
                    f"cwe={spec.cwe} attempt={attempt} reason={reason}"
                )
                append_jsonl(
                    rejected_path,
                    {
                        "context": spec.to_dict(),
                        "cwe": spec.cwe,
                        "attempt": attempt,
                        "provider": args.provider,
                        "model": model,
                        "reject_reason": [reason],
                        "error": str(exc),
                    },
                )
                rejected += 1

        if not accepted_for_spec:
            print(f"failed to accept {spec.cwe} {spec.mode} after {args.max_attempts} attempts")

    if not args.no_export:
        counts = export_records(read_jsonl(samples_path), output_dir / "vudenc")
        for mode, count in counts.items():
            print(f"exported {count:4d} samples to plain_{mode}")

    print(f"done: accepted={accepted}, rejected={rejected}, samples={samples_path}, rejected_log={rejected_path}")
    return 0


def _build_record(
    sample_id: str,
    spec: GenerationSpec,
    candidate: Any,
    validation: dict[str, Any],
    attempt: int,
) -> dict[str, Any]:
    return {
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


if __name__ == "__main__":
    raise SystemExit(main())
