"""Train controlled A/B/C Word2Vec models on a prepared experiment release.

Run this module from the Lab 3 ``vudenc`` Conda environment. Dependencies are
loaded lazily so dataset preparation does not require TensorFlow or Gensim.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from .experiment_data import CANONICAL_MODES, read_jsonl


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared", type=Path, default=Path("experiments/release_91_v1"))
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--word2vec", type=Path, default=Path("../w2v/word2vec_withString10-300-200.model"))
    parser.add_argument("--word2vec-corpus", type=Path, default=Path("../w2v/pythontraining.txt"))
    parser.add_argument("--models", nargs="+", choices=("lstm", "mlp", "random_forest", "cnn"), default=("lstm", "mlp", "random_forest", "cnn"))
    parser.add_argument("--conditions", nargs="+", choices=("A", "B", "C"), default=("A", "B", "C"))
    parser.add_argument("--modes", nargs="+", choices=CANONICAL_MODES, default=CANONICAL_MODES)
    parser.add_argument("--seed", type=int, default=20260624)
    parser.add_argument("--epochs", type=int, default=100)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--smoke", action="store_true", help="Run one epoch/tree per selected model for CPU verification.")
    return parser


def _dependencies() -> tuple[Any, Any, Any, Any, Any]:
    try:
        import joblib
        import numpy as np
        import tensorflow as tf
        from gensim.models import Word2Vec
        from sklearn import metrics
    except ImportError as exc:
        raise SystemExit(
            "Experiment dependencies are missing. Activate the Lab 3 vudenc Conda environment and install requirements-experiments.txt."
        ) from exc
    return joblib, np, tf, Word2Vec, metrics


def set_seeds(seed: int, np: Any, tf: Any) -> None:
    os.environ["PYTHONHASHSEED"] = str(seed)
    random.seed(seed)
    np.random.seed(seed)
    tf.keras.utils.set_random_seed(seed)
    try:
        tf.config.experimental.enable_op_determinism()
    except (AttributeError, RuntimeError):
        pass


def vectorize(rows: list[dict[str, Any]], keyed_vectors: Any, np: Any, sequence: bool) -> tuple[Any, Any]:
    dimension = int(keyed_vectors.vector_size)
    if sequence:
        features = np.zeros((len(rows), 200), dtype="int32")
        for row_index, row in enumerate(rows):
            for token_index, token in enumerate(row["tokens"][:200]):
                vector_index = keyed_vectors.key_to_index.get(token)
                if vector_index is not None:
                    features[row_index, token_index] = vector_index + 1
    else:
        features = np.zeros((len(rows), dimension), dtype="float32")
        for row_index, row in enumerate(rows):
            vectors = [keyed_vectors[token] for token in row["tokens"] if token in keyed_vectors]
            if vectors:
                features[row_index] = np.mean(vectors, axis=0)
    labels = np.asarray([int(row["label"]) for row in rows], dtype="int32")
    return features, labels


def _f1_callback(tf: Any) -> Any:
    class ValidationF1(tf.keras.callbacks.Callback):
        def __init__(self, validation_data: tuple[Any, Any]) -> None:
            super().__init__()
            self.features, self.labels = validation_data
            self.best = -1.0

        def on_epoch_end(self, epoch: int, logs: dict[str, Any] | None = None) -> None:
            from sklearn.metrics import f1_score

            predicted = (self.model.predict(self.features, verbose=0).ravel() >= 0.5).astype("int32")
            value = float(f1_score(self.labels, predicted, zero_division=0))
            (logs if logs is not None else {})["val_f1"] = value
            self.best = max(self.best, value)

    return ValidationF1


def build_neural_model(model_name: str, tf: Any, embedding_matrix: Any) -> Any:
    inputs = tf.keras.Input(shape=(200,), dtype="int32")
    x = tf.keras.layers.Embedding(
        input_dim=embedding_matrix.shape[0],
        output_dim=embedding_matrix.shape[1],
        weights=[embedding_matrix],
        trainable=False,
    )(inputs)
    if model_name == "lstm":
        x = tf.keras.layers.LSTM(100, dropout=0.2)(x)
    elif model_name == "cnn":
        x = tf.keras.layers.Conv1D(128, 5, activation="relu")(x)
        x = tf.keras.layers.GlobalMaxPooling1D()(x)
        x = tf.keras.layers.Dense(128, activation="relu")(x)
        x = tf.keras.layers.Dropout(0.2)(x)
    else:
        raise ValueError(f"not a neural sequence model: {model_name}")
    outputs = tf.keras.layers.Dense(1, activation="sigmoid")(x)
    model = tf.keras.Model(inputs, outputs)
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    return model


def _metric_row(metrics: Any, y_true: Any, y_pred: Any, *, mode: str, condition: str, model: str) -> dict[str, Any]:
    matrix = metrics.confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist()
    return {
        "mode": mode,
        "condition": condition,
        "model": model,
        "accuracy": float(metrics.accuracy_score(y_true, y_pred)),
        "precision": float(metrics.precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(metrics.recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(metrics.f1_score(y_true, y_pred, zero_division=0)),
        "macro_f1": float(metrics.f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "support": int(len(y_true)),
        "positive_support": int(sum(y_true)),
        "confusion_matrix": matrix,
    }


def _rows_for(rows: list[dict[str, Any]], dataset: str, mode: str, split: str) -> list[dict[str, Any]]:
    return [row for row in rows if row["dataset"] == dataset and row["mode"] == mode and row["split"] == split]


def condition_rows(
    real_train: list[dict[str, Any]],
    real_validation: list[dict[str, Any]],
    synthetic_train: list[dict[str, Any]],
    synthetic_validation: list[dict[str, Any]],
) -> dict[str, tuple[list[dict[str, Any]], list[dict[str, Any]]]]:
    return {
        "A": (real_train, real_validation),
        "B": (synthetic_train, synthetic_validation),
        "C": (real_train + synthetic_train, real_validation),
    }


def _write_feature_cache(out: Path, name: str, values: Any, labels: Any, np: Any) -> None:
    out.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(out / f"{name}.npz", features=values, labels=labels)


def embedding_matrix(keyed_vectors: Any, np: Any) -> Any:
    matrix = np.zeros((len(keyed_vectors.key_to_index) + 1, keyed_vectors.vector_size), dtype="float32")
    matrix[1:] = keyed_vectors.vectors
    return matrix


class PythonCorpus:
    """Re-iterable streaming corpus for Gensim's multi-epoch training."""

    token_pattern = re.compile(r"[A-Za-z_]\w*|\d+(?:\.\d+)?|==|!=|<=|>=|//|<<|>>|\*\*|[^\s]")

    def __init__(self, path: Path) -> None:
        self.path = path

    def __iter__(self) -> Any:
        buffer: list[str] = []
        with self.path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                buffer.extend(match.group(0).lower() for match in self.token_pattern.finditer(line))
                while len(buffer) >= 200:
                    yield buffer[:200]
                    buffer = buffer[200:]
        if buffer:
            yield buffer


def load_or_rebuild_word2vec(Word2Vec: Any, source: Path, corpus: Path, out: Path, seed: int) -> Any:
    try:
        return Word2Vec.load(str(source)).wv
    except (FileNotFoundError, OSError, ValueError) as exc:
        rebuilt = out / "word2vec" / "word2vec_rebuilt_10-5-300.model"
        if rebuilt.is_file():
            print(f"saved Word2Vec artifact is unavailable ({exc}); loading rebuilt artifact")
            return Word2Vec.load(str(rebuilt)).wv
        if not corpus.is_file():
            raise SystemExit(f"Word2Vec artifact is unavailable and corpus does not exist: {corpus}") from exc
        print(f"saved Word2Vec artifact is unavailable ({exc}); rebuilding from {corpus}")
        model = Word2Vec(
            sentences=PythonCorpus(corpus), vector_size=300, window=10,
            min_count=10, workers=4, epochs=5, seed=seed,
        )
        rebuilt.parent.mkdir(parents=True, exist_ok=True)
        model.save(str(rebuilt))
        return model.wv


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    joblib, np, tf, Word2Vec, metrics = _dependencies()
    set_seeds(args.seed, np, tf)
    out = args.out or args.prepared / "results"
    out.mkdir(parents=True, exist_ok=True)
    rows = read_jsonl(args.prepared / "manifests" / "windows.jsonl")
    word2vec = load_or_rebuild_word2vec(Word2Vec, args.word2vec, args.word2vec_corpus, out, args.seed)
    embeddings = embedding_matrix(word2vec, np)
    results: list[dict[str, Any]] = []
    feature_cache: dict[tuple[str, str, str, bool], tuple[Any, Any]] = {}

    def features(dataset: str, mode: str, split: str, sequence: bool) -> tuple[Any, Any]:
        key = (dataset, mode, split, sequence)
        if key not in feature_cache:
            values, labels = vectorize(_rows_for(rows, dataset, mode, split), word2vec, np, sequence)
            feature_cache[key] = (values, labels)
            representation = "token_ids" if sequence else "mean_word2vec"
            _write_feature_cache(
                out / "feature_cache",
                f"{mode}_{dataset}_{split}_{representation}",
                values,
                labels,
                np,
            )
        return feature_cache[key]

    for mode in args.modes:
        real_train = _rows_for(rows, "real", mode, "train")
        real_validation = _rows_for(rows, "real", mode, "validation")
        real_test = _rows_for(rows, "real", mode, "test")
        synthetic_train = _rows_for(rows, "synthetic", mode, "train")
        synthetic_validation = _rows_for(rows, "synthetic", mode, "validation")
        if not real_train or not real_validation or not real_test or not synthetic_train or not synthetic_validation:
            raise SystemExit(f"{mode}: missing required train/validation/test windows in prepared release")
        conditions = condition_rows(real_train, real_validation, synthetic_train, synthetic_validation)
        for condition in args.conditions:
            train_rows, validation_rows = conditions[condition]
            for model_name in args.models:
                sequence = model_name in {"lstm", "cnn"}
                if condition == "C":
                    real_features, real_labels = features("real", mode, "train", sequence)
                    synthetic_features, synthetic_labels = features("synthetic", mode, "train", sequence)
                    x_train = np.concatenate((real_features, synthetic_features))
                    y_train = np.concatenate((real_labels, synthetic_labels))
                else:
                    dataset = "real" if condition == "A" else "synthetic"
                    x_train, y_train = features(dataset, mode, "train", sequence)
                validation_dataset = "real" if condition in {"A", "C"} else "synthetic"
                x_validation, y_validation = features(validation_dataset, mode, "validation", sequence)
                x_test, y_test = features("real", mode, "test", sequence)
                cache_name = f"{mode}_{condition}_{model_name}"
                if model_name in {"lstm", "cnn"}:
                    model = build_neural_model(model_name, tf, embeddings)
                    callback_type = _f1_callback(tf)
                    callbacks = [
                        callback_type((x_validation, y_validation)),
                        tf.keras.callbacks.EarlyStopping(monitor="val_f1", mode="max", patience=10, restore_best_weights=True),
                    ]
                    model.fit(
                        x_train, y_train,
                        validation_data=(x_validation, y_validation),
                        epochs=1 if args.smoke else args.epochs,
                        batch_size=args.batch_size,
                        verbose=0,
                        callbacks=callbacks,
                    )
                    predicted = (model.predict(x_test, verbose=0).ravel() >= 0.5).astype("int32")
                    model_path = out / "models" / f"{cache_name}.keras"
                    model_path.parent.mkdir(parents=True, exist_ok=True)
                    model.save(model_path)
                elif model_name == "mlp":
                    from sklearn.neural_network import MLPClassifier

                    model = MLPClassifier(
                        hidden_layer_sizes=(256, 128), activation="relu", solver="adam",
                        max_iter=1 if args.smoke else 500, random_state=args.seed,
                    )
                    model.fit(x_train, y_train)
                    predicted = model.predict(x_test)
                    model_path = out / "models" / f"{cache_name}.joblib"
                    model_path.parent.mkdir(parents=True, exist_ok=True)
                    joblib.dump(model, model_path)
                else:
                    from sklearn.ensemble import RandomForestClassifier

                    model = RandomForestClassifier(
                        n_estimators=1 if args.smoke else 300, class_weight="balanced",
                        random_state=args.seed, n_jobs=-1,
                    )
                    model.fit(x_train, y_train)
                    predicted = model.predict(x_test)
                    model_path = out / "models" / f"{cache_name}.joblib"
                    model_path.parent.mkdir(parents=True, exist_ok=True)
                    joblib.dump(model, model_path)
                row = _metric_row(metrics, y_test, predicted, mode=mode, condition=condition, model=model_name)
                results.append(row)
                matrix_path = out / "confusion_matrices" / f"{cache_name}.json"
                matrix_path.parent.mkdir(parents=True, exist_ok=True)
                matrix_path.write_text(json.dumps(row["confusion_matrix"], indent=2) + "\n", encoding="utf-8")
                print(f"completed {mode} {condition} {model_name}: f1={row['f1']:.3f}")

    _write_reports(out, results)
    return 0


def _write_reports(out: Path, results: list[dict[str, Any]]) -> None:
    fields = ["mode", "condition", "model", "accuracy", "precision", "recall", "f1", "macro_f1", "support", "positive_support"]
    with (out / "metrics.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows({field: row[field] for field in fields} for row in results)
    (out / "metrics.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    grouped: dict[tuple[str, str], list[float]] = defaultdict(list)
    for row in results:
        grouped[(row["model"], row["condition"])].append(row["macro_f1"])
    lines = ["# Controlled A/B/C Results", "", "| Model | Condition | Mean macro-F1 across CWEs |", "|---|---:|---:|"]
    for (model, condition), values in sorted(grouped.items()):
        lines.append(f"| {model} | {condition} | {sum(values) / len(values):.4f} |")
    lines.extend(["", "All rows use the identical held-out real-VUDENC test split for each CWE. F1 is the primary metric."])
    (out / "comparison.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
