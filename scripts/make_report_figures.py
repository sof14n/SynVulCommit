from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "report" / "images"
EXPERIMENT = ROOT / "experiments" / "release_91_v1"
CORPUS = ROOT / "output_deepseekpro_glmreview_100_per_cwe" / "samples.jsonl"

MODE_LABELS = {
    "sql": "SQLi",
    "command_injection": "Command",
    "directory_traversal": "Path",
    "open_redirect": "Redirect",
    "remote_code_execution": "RCE",
    "xss": "XSS",
    "xsrf": "XSRF",
}


def save_figure(name: str) -> None:
    plt.tight_layout()
    plt.savefig(OUTPUT / f"{name}.pdf", bbox_inches="tight")
    plt.savefig(OUTPUT / f"{name}.png", dpi=220, bbox_inches="tight")
    plt.close()


def corpus_coverage() -> None:
    counts: Counter[str] = Counter()
    for line in CORPUS.read_text(encoding="utf-8").splitlines():
        if line.strip():
            counts[json.loads(line)["mode"]] += 1
    modes = list(MODE_LABELS)
    values = [counts[mode] for mode in modes]
    plt.figure(figsize=(7.1, 3.5))
    bars = plt.bar(range(len(modes)), values, color="#267a9d")
    plt.axhline(91, color="#a1442e", linewidth=1.2, linestyle="--", label="Frozen subset target")
    plt.xticks(range(len(modes)), [MODE_LABELS[mode] for mode in modes])
    plt.ylabel("Accepted commit pairs")
    plt.ylim(0, 112)
    plt.legend(frameon=False, loc="lower right")
    for bar, value in zip(bars, values):
        plt.text(bar.get_x() + bar.get_width() / 2, value + 1, str(value), ha="center", fontsize=8)
    save_figure("corpus_coverage")


def abcs_results() -> None:
    rows = list(csv.DictReader((EXPERIMENT / "results" / "metrics.csv").open(encoding="utf-8")))
    grouped: dict[tuple[str, str], list[float]] = defaultdict(list)
    for row in rows:
        grouped[(row["model"], row["condition"])].append(float(row["macro_f1"]))
    models = ["lstm", "mlp", "random_forest", "cnn"]
    conditions = ["A", "B", "C"]
    labels = {"A": "A: real", "B": "B: synthetic", "C": "C: combined"}
    colors = {"A": "#235789", "B": "#c75c36", "C": "#4a9b6e"}
    x = np.arange(len(models))
    width = 0.23
    plt.figure(figsize=(7.2, 3.8))
    for index, condition in enumerate(conditions):
        values = [sum(grouped[(model, condition)]) / len(grouped[(model, condition)]) for model in models]
        plt.bar(x + (index - 1) * width, values, width, label=labels[condition], color=colors[condition])
    plt.xticks(x, ["LSTM", "MLP", "Random Forest", "CNN"])
    plt.ylabel("Mean macro-F1 across CWEs")
    plt.ylim(0, 0.75)
    plt.legend(frameon=False, ncol=3, loc="upper center")
    plt.grid(axis="y", alpha=0.2)
    save_figure("abc_macro_f1")


def label_distribution() -> None:
    rows = [json.loads(line) for line in (EXPERIMENT / "manifests" / "windows.jsonl").read_text(encoding="utf-8").splitlines() if line]
    values: dict[str, list[int]] = {}
    for dataset in ("real", "synthetic"):
        selected = [row for row in rows if row["dataset"] == dataset and row["split"] == "train"]
        positives = sum(int(row["label"]) for row in selected)
        values[dataset] = [positives, len(selected) - positives]
    x = np.arange(2)
    plt.figure(figsize=(5.6, 3.6))
    plt.bar(x, [values["real"][0], values["synthetic"][0]], color="#c75c36", label="Vulnerable label")
    plt.bar(x, [values["real"][1], values["synthetic"][1]], bottom=[values["real"][0], values["synthetic"][0]], color="#4a9b6e", label="Clean label")
    plt.xticks(x, ["Real VUDENC train", "Synthetic train"])
    plt.ylabel("Training windows")
    plt.legend(frameon=False)
    for index, dataset in enumerate(("real", "synthetic")):
        total = sum(values[dataset])
        plt.text(index, total + 75, f"{total} total", ha="center", fontsize=8)
    plt.ylim(0, 5900)
    save_figure("training_label_distribution")


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    corpus_coverage()
    abcs_results()
    label_distribution()


if __name__ == "__main__":
    main()
