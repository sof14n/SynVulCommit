from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline

from .dataset import CodeExample, build_examples, split_real_examples
from .vudenc_loader import load_modes


DEFAULT_MODES = ("sql", "command_injection", "xss")


def run_experiment(
    *,
    vudenc_root: Path,
    synthetic_root: Path,
    output_dir: Path,
    modes: list[str],
    seed: int = 1337,
    context_chars: int = 600,
    negative_ratio: int = 2,
) -> dict[str, Any]:
    real_records = load_modes(vudenc_root, modes, origin="vudenc")
    synthetic_records = load_modes(synthetic_root, modes, origin="synthetic")
    real_examples = build_examples(real_records, context_chars=context_chars, negative_ratio=negative_ratio, seed=seed)
    synthetic_examples = build_examples(synthetic_records, context_chars=context_chars, negative_ratio=negative_ratio, seed=seed)
    splits = split_real_examples(real_examples)

    results: dict[str, Any] = {
        "modes": modes,
        "settings": {
            "seed": seed,
            "context_chars": context_chars,
            "negative_ratio": negative_ratio,
            "classifier": "tfidf_char_ngrams_logistic_regression",
        },
        "data": {
            "real_records": len(real_records),
            "synthetic_records": len(synthetic_records),
            "real_examples": len(real_examples),
            "synthetic_examples": len(synthetic_examples),
            "real_train_examples": len(splits["train"]),
            "real_validation_examples": len(splits["validation"]),
            "real_test_examples": len(splits["test"]),
        },
        "experiments": {},
    }

    for mode in modes:
        train_real = [example for example in splits["train"] if example.mode == mode]
        test_real = [example for example in splits["test"] if example.mode == mode]
        train_synthetic = [example for example in synthetic_examples if example.mode == mode]
        results["experiments"][mode] = {
            "model_a_vudenc_only": _train_and_score(train_real, test_real),
            "model_b_synthetic_only": _train_and_score(train_synthetic, test_real),
            "model_c_mixed": _train_and_score(train_real + train_synthetic, test_real),
        }

    results["macro_f1"] = _macro_f1_by_model(results["experiments"])
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "metrics.json").write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_examples(output_dir / "dataset_summary.jsonl", real_examples, synthetic_examples, splits)
    return results


def _train_and_score(train: list[CodeExample], test: list[CodeExample]) -> dict[str, Any]:
    if not train or not test:
        return {
            "status": "skipped",
            "reason": "missing train or test examples",
            "train_examples": len(train),
            "test_examples": len(test),
        }
    if len({example.label for example in train}) < 2:
        return {
            "status": "skipped",
            "reason": "training split has one class",
            "train_examples": len(train),
            "test_examples": len(test),
        }

    model = Pipeline(
        [
            ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1)),
            ("clf", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=1337)),
        ]
    )
    x_train = [example.text for example in train]
    y_train = [example.label for example in train]
    x_test = [example.text for example in test]
    y_test = [example.label for example in test]
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    return {
        "status": "ok",
        "train_examples": len(train),
        "test_examples": len(test),
        "train_positive": sum(y_train),
        "test_positive": sum(y_test),
        "accuracy": round(float(accuracy_score(y_test, predictions)), 6),
        "precision": round(float(precision_score(y_test, predictions, zero_division=0)), 6),
        "recall": round(float(recall_score(y_test, predictions, zero_division=0)), 6),
        "f1": round(float(f1_score(y_test, predictions, zero_division=0)), 6),
    }


def _macro_f1_by_model(experiments: dict[str, Any]) -> dict[str, float | None]:
    model_names = ("model_a_vudenc_only", "model_b_synthetic_only", "model_c_mixed")
    macro: dict[str, float | None] = {}
    for model_name in model_names:
        values = [
            float(mode_results[model_name]["f1"])
            for mode_results in experiments.values()
            if mode_results.get(model_name, {}).get("status") == "ok"
        ]
        macro[model_name] = round(sum(values) / len(values), 6) if values else None
    return macro


def _write_examples(
    path: Path,
    real_examples: list[CodeExample],
    synthetic_examples: list[CodeExample],
    splits: dict[str, list[CodeExample]],
) -> None:
    rows = [
        {"name": "real", "count": len(real_examples), "positive": sum(example.label for example in real_examples)},
        {
            "name": "synthetic",
            "count": len(synthetic_examples),
            "positive": sum(example.label for example in synthetic_examples),
        },
    ]
    rows.extend(
        {"name": f"real_{split}", "count": len(examples), "positive": sum(example.label for example in examples)}
        for split, examples in splits.items()
    )
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def print_report(results: dict[str, Any]) -> None:
    print("SynVulCommit evaluation")
    print(f"modes: {', '.join(results['modes'])}")
    print(f"real examples: {results['data']['real_examples']}")
    print(f"synthetic examples: {results['data']['synthetic_examples']}")
    print("macro F1:")
    for model_name, value in results["macro_f1"].items():
        print(f"  {model_name}: {value}")
    for mode, experiments in results["experiments"].items():
        print(f"{mode}:")
        for model_name, metrics in experiments.items():
            if metrics["status"] != "ok":
                print(f"  {model_name}: skipped ({metrics['reason']})")
                continue
            print(
                f"  {model_name}: f1={metrics['f1']} precision={metrics['precision']} "
                f"recall={metrics['recall']} train={metrics['train_examples']} test={metrics['test_examples']}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Model A/B/C SynVulCommit evaluation on VUDENC-format datasets.")
    parser.add_argument("--vudenc-root", required=True, help="Directory containing real VUDENC plain_<mode> files.")
    parser.add_argument("--synthetic-root", required=True, help="Directory containing synthetic plain_<mode> files.")
    parser.add_argument("--output", default="output/evaluation", help="Directory for metrics.json and summaries.")
    parser.add_argument("--mode", action="append", dest="modes", help="Mode to evaluate. Repeat for multiple modes.")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--context-chars", type=int, default=600)
    parser.add_argument("--negative-ratio", type=int, default=2)
    args = parser.parse_args()

    results = run_experiment(
        vudenc_root=Path(args.vudenc_root),
        synthetic_root=Path(args.synthetic_root),
        output_dir=Path(args.output),
        modes=args.modes or list(DEFAULT_MODES),
        seed=args.seed,
        context_chars=args.context_chars,
        negative_ratio=args.negative_ratio,
    )
    print_report(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
