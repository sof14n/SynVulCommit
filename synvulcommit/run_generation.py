from __future__ import annotations

import argparse
import hashlib
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .cwe_registry import all_cwes
from .diversity import DiversityIndex
from .export_vudenc import export_records
from .llm_generator import GenerationError, generate_commit, provider_model_name
from .prompt_builder import build_prompt
from .spec_sampler import GenerationSpec, iter_specs, make_spec
from .storage import append_jsonl, ensure_output_files, next_sample_id, read_jsonl
from .validator import validate_candidate


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate validated synthetic Python vulnerability-fix commits.")
    parser.add_argument("--per-cwe", type=int, default=1, help="Accepted samples to generate per CWE.")
    parser.add_argument("--target-per-cwe", type=int, help="Resume until each selected CWE has this many accepted samples.")
    parser.add_argument("--provider", default="mock", choices=("mock", "openai_compatible", "local_http"))
    parser.add_argument("--output", default="output", help="Output directory.")
    parser.add_argument("--seed", type=int, default=1337, help="Random seed for task sampling.")
    parser.add_argument("--max-attempts", type=int, default=5, help="Generation attempts per requested spec.")
    parser.add_argument("--cwe", action="append", help="Limit generation to one or more CWE keys/modes, e.g. --cwe xsrf --cwe sql.")
    parser.add_argument("--require-tools", action="store_true", help="Fail validation if Bandit or Semgrep is missing.")
    parser.add_argument("--production", action="store_true", help="Enable guardrails for real dataset generation.")
    parser.add_argument("--no-export", action="store_true", help="Do not export VUDENC-style files after generation.")
    args = parser.parse_args()

    production_error = validate_production_settings(args.provider, args.require_tools, args.production)
    if production_error:
        print(production_error)
        return 2

    output_dir = Path(args.output)
    samples_path, rejected_path = ensure_output_files(output_dir)
    existing_records = read_jsonl(samples_path)
    diversity = DiversityIndex()
    diversity.load_existing(existing_records)

    rules_dir = Path(__file__).resolve().parent / "rules"
    temp_root = output_dir / "tmp"

    accepted = 0
    rejected = 0
    plan = build_generation_plan(
        per_cwe=args.per_cwe,
        target_per_cwe=args.target_per_cwe,
        existing_records=existing_records,
        seed=args.seed,
        cwe_filters=args.cwe,
    )
    if not plan["matched"]:
        print(f"no specs matched --cwe values: {', '.join(args.cwe or [])}")
        return 2
    specs = plan["specs"]
    run_stats = plan["stats"]
    if args.target_per_cwe is not None and not specs:
        print(f"all selected CWEs already have at least {args.target_per_cwe} accepted samples")
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
                    model=provider_model_name(args.provider),
                    prompt_sha256=_sha256_text(prompt),
                    seed=args.seed,
                    validation=validation.to_dict(),
                    attempt=attempt,
                )

                if not validation.passed:
                    append_jsonl(rejected_path, {**record, "reject_reason": validation.reasons})
                    rejected += 1
                    run_stats[spec.mode]["rejected"] += 1
                    continue

                diverse, reason = diversity.accepts(record)
                if not diverse:
                    append_jsonl(rejected_path, {**record, "reject_reason": [reason]})
                    rejected += 1
                    run_stats[spec.mode]["rejected"] += 1
                    continue

                append_jsonl(samples_path, record)
                existing_records.append(record)
                accepted += 1
                run_stats[spec.mode]["accepted"] += 1
                accepted_for_spec = True
                print(f"accepted {record['id']} ({spec.cwe} {spec.mode})")
                break
            except GenerationError as exc:
                model = provider_model_name(args.provider)
                reason = getattr(exc, "reason", "generation_error")
                field_path = getattr(exc, "field_path", None)
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
                        "invalid_field": field_path,
                        "error": str(exc),
                    },
                )
                rejected += 1
                run_stats[spec.mode]["rejected"] += 1

        if not accepted_for_spec:
            print(f"failed to accept {spec.cwe} {spec.mode} after {args.max_attempts} attempts")

    print_run_summary(run_stats, target_per_cwe=args.target_per_cwe)

    if not args.no_export:
        counts = export_records(read_jsonl(samples_path), output_dir / "vudenc")
        for mode, count in counts.items():
            print(f"exported {count:4d} samples to plain_{mode}")

    print(f"done: accepted={accepted}, rejected={rejected}, samples={samples_path}, rejected_log={rejected_path}")
    return 0


def build_generation_plan(
    per_cwe: int,
    target_per_cwe: int | None,
    existing_records: list[dict[str, Any]],
    seed: int,
    cwe_filters: list[str] | None = None,
) -> dict[str, Any]:
    existing_by_mode = count_existing_by_mode(existing_records)
    wanted = {value.lower().strip() for value in cwe_filters or []}
    selected = [
        definition
        for definition in all_cwes()
        if not wanted or definition.key in wanted or definition.mode in wanted or definition.cwe.lower() in wanted
    ]
    if cwe_filters and not selected:
        return {"matched": False, "specs": [], "stats": {}}

    stats = {
        definition.mode: {
            "cwe": definition.cwe,
            "existing": existing_by_mode.get(definition.mode, 0),
            "target": target_per_cwe,
            "planned": 0,
            "accepted": 0,
            "rejected": 0,
            "remaining": 0,
        }
        for definition in selected
    }

    if target_per_cwe is None:
        specs = [spec for spec in iter_specs(per_cwe, seed=seed) if spec.mode in stats]
        for spec in specs:
            stats[spec.mode]["planned"] += 1
        return {"matched": True, "specs": specs, "stats": stats}

    rng = random.Random(seed)
    specs: list[GenerationSpec] = []
    for definition in selected:
        existing = existing_by_mode.get(definition.mode, 0)
        needed = max(target_per_cwe - existing, 0)
        stats[definition.mode]["planned"] = needed
        stats[definition.mode]["remaining"] = needed
        for offset in range(needed):
            specs.append(make_spec(definition, existing + offset, rng))
    rng.shuffle(specs)
    return {"matched": True, "specs": specs, "stats": stats}


def count_existing_by_mode(records: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        mode = str(record.get("mode") or record.get("context", {}).get("mode", ""))
        if mode:
            counts[mode] = counts.get(mode, 0) + 1
    return counts


def print_run_summary(stats: dict[str, dict[str, Any]], target_per_cwe: int | None) -> None:
    if not stats:
        return
    print("run summary:")
    for mode in sorted(stats):
        item = stats[mode]
        remaining = item["remaining"]
        if target_per_cwe is not None:
            remaining = max(int(item["target"]) - int(item["existing"]) - int(item["accepted"]), 0)
        print(
            f"  {item['cwe']} {mode}: existing={item['existing']} planned={item['planned']} "
            f"accepted={item['accepted']} rejected={item['rejected']} remaining={remaining}"
        )


def _build_record(
    sample_id: str,
    spec: GenerationSpec,
    candidate: Any,
    model: str,
    prompt_sha256: str,
    seed: int,
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
        "seed": seed,
        "generated_at": _utc_now(),
        "prompt_sha256": prompt_sha256,
        "commit_message": candidate.commit_message,
        "filename": candidate.filename,
        "vulnerable_code": candidate.vulnerable_code,
        "fixed_code": candidate.fixed_code,
        "diff": candidate.diff,
        "badparts": candidate.badparts,
        "goodparts": candidate.goodparts,
        "provider": candidate.provider,
        "model": model,
        "validation": validation,
        "validation_summary": _validation_summary(validation),
    }


def validate_production_settings(provider: str, require_tools: bool, production: bool) -> str | None:
    if not production:
        return None
    if provider == "mock":
        return "production mode refuses --provider mock; use --provider openai_compatible or --provider local_http."
    if not require_tools:
        return "production mode requires --require-tools so Bandit and Semgrep must run."
    model = provider_model_name(provider)
    if not model or model == "<unset>":
        if provider == "openai_compatible":
            return "production mode requires SYNVUL_MODEL for provider/model metadata."
        if provider == "local_http":
            return "production mode requires SYNVUL_LOCAL_MODEL for provider/model metadata."
        return "production mode requires provider/model metadata."
    return None


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _validation_summary(validation: dict[str, Any]) -> dict[str, Any]:
    tool_results = validation.get("tool_results", {})
    return {
        "passed": bool(validation.get("passed")),
        "reason_count": len(validation.get("reasons") or []),
        "bandit_findings": len(tool_results.get("bandit", {}).get("findings") or []),
        "semgrep_findings": len(tool_results.get("semgrep", {}).get("findings") or []),
    }


if __name__ == "__main__":
    raise SystemExit(main())
