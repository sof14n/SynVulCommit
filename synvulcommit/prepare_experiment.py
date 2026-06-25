"""Prepare a frozen A/B/C experiment release from VUDENC and SynVulCommit data."""

from __future__ import annotations

import argparse
import json
import shutil
from collections import Counter
from pathlib import Path

from .experiment_data import (
    CANONICAL_MODES,
    load_synthetic_records,
    load_vudenc_records,
    cap_windows,
    select_audit_pairs,
    select_balanced_synthetic,
    select_real_cap,
    split_commits,
    token_windows,
    write_jsonl,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--synthetic", type=Path, default=Path("output_deepseekpro_glmreview_100_per_cwe/samples.jsonl"))
    parser.add_argument("--vudenc-root", type=Path, default=Path("../data"))
    parser.add_argument("--out", type=Path, default=Path("experiments/release_91_v1"))
    parser.add_argument("--per-cwe", type=int, default=91)
    parser.add_argument("--seed", type=int, default=20260624)
    parser.add_argument("--window-size", type=int, default=200)
    parser.add_argument("--stride", type=int, default=5)
    parser.add_argument("--max-positive-windows", type=int, default=4)
    parser.add_argument("--max-negative-windows", type=int, default=4)
    parser.add_argument("--synthetic-verification", type=Path, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    synthetic = select_balanced_synthetic(load_synthetic_records(args.synthetic), args.per_cwe, args.seed)
    real = select_real_cap(load_vudenc_records(args.vudenc_root), args.per_cwe, args.seed)
    all_records = synthetic + real
    splits = split_commits(all_records, args.seed)
    out = args.out
    write_jsonl(out / "manifests" / "synthetic_selected.jsonl", (item.manifest() for item in synthetic))
    write_jsonl(out / "manifests" / "real_selected.jsonl", (item.manifest() for item in real))
    seen_groups: set[str] = set()
    split_rows = []
    for record in all_records:
        if record.group_id in seen_groups:
            continue
        seen_groups.add(record.group_id)
        split_rows.append({"group_id": record.group_id, "dataset": record.dataset, "mode": record.mode, "split": splits[record.group_id]})
    write_jsonl(out / "manifests" / "commit_splits.jsonl", split_rows)
    windows = []
    unbounded_window_count = 0
    for record in all_records:
        generated_windows = token_windows(record, args.window_size, args.stride)
        unbounded_window_count += len(generated_windows)
        for window in cap_windows(
            generated_windows,
            args.max_positive_windows,
            args.max_negative_windows,
            args.seed,
        ):
            window["split"] = splits[record.group_id]
            windows.append(window)
    write_jsonl(out / "manifests" / "windows.jsonl", windows)
    write_jsonl(out / "audit" / "synthetic_pairs_for_manual_review.jsonl", select_audit_pairs(synthetic, 5, args.seed))
    def group_counts(records: list[object]) -> dict[str, int]:
        return {
            mode: len({record.group_id for record in records if record.mode == mode})
            for mode in CANONICAL_MODES
        }

    verification_source = args.synthetic_verification or args.synthetic.parent / "dataset_verification.json"
    if verification_source.is_file():
        audit_path = out / "audit" / "source_dataset_verification.json"
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(verification_source, audit_path)
    summary = {
        "seed": args.seed,
        "per_cwe": args.per_cwe,
        "max_positive_windows_per_file": args.max_positive_windows,
        "max_negative_windows_per_file": args.max_negative_windows,
        "modes": list(CANONICAL_MODES),
        "synthetic_commits": group_counts(synthetic),
        "real_commits": group_counts(real),
        "synthetic_file_records": dict(Counter(record.mode for record in synthetic)),
        "real_file_records": dict(Counter(record.mode for record in real)),
        "windows": dict(Counter(f"{row['dataset']}:{row['split']}" for row in windows)),
        "unbounded_window_count": unbounded_window_count,
        "selected_window_count": len(windows),
        "positive_windows": sum(row["label"] for row in windows),
        "negative_windows": sum(not row["label"] for row in windows),
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / "dataset_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"prepared {len(synthetic)} synthetic records ({len({item.group_id for item in synthetic})} commit groups) "
        f"and {len(real)} real file records ({len({item.group_id for item in real})} commit groups) in {out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
