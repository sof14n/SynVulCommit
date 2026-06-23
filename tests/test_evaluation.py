from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from synvulcommit.evaluation.dataset import build_examples, split_real_examples
from synvulcommit.evaluation.train_eval import run_experiment
from synvulcommit.evaluation.vudenc_loader import load_plain_file


class EvaluationTests(unittest.TestCase):
    def test_loader_reads_vudenc_plain_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_plain(root / "plain_sql", mode="sql", count=1)

            records = load_plain_file(root / "plain_sql", mode="sql", origin="fixture")

        self.assertEqual(1, len(records))
        self.assertEqual("sql", records[0].mode)
        self.assertEqual(("query = f\"SELECT * FROM users WHERE name = '{name}'\"",), records[0].badparts)

    def test_examples_include_positive_and_negative_windows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_plain(root / "plain_sql", mode="sql", count=1)
            records = load_plain_file(root / "plain_sql", mode="sql", origin="fixture")

            examples = build_examples(records, context_chars=120, negative_ratio=1)

        self.assertGreaterEqual(sum(example.label for example in examples), 1)
        self.assertGreaterEqual(sum(1 for example in examples if example.label == 0), 1)

    def test_split_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_plain(root / "plain_sql", mode="sql", count=8)
            records = load_plain_file(root / "plain_sql", mode="sql", origin="fixture")
            examples = build_examples(records, context_chars=120, negative_ratio=1)

            first = split_real_examples(examples)
            second = split_real_examples(examples)

        self.assertEqual(first, second)

    def test_run_experiment_writes_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real_root = root / "real"
            synthetic_root = root / "synthetic"
            output = root / "out"
            _write_plain(real_root / "plain_sql", mode="sql", count=12)
            _write_plain(synthetic_root / "plain_sql", mode="sql", count=3)

            results = run_experiment(
                vudenc_root=real_root,
                synthetic_root=synthetic_root,
                output_dir=output,
                modes=["sql"],
                context_chars=120,
                negative_ratio=1,
            )

            self.assertTrue((output / "metrics.json").is_file())
        self.assertIn("model_a_vudenc_only", results["experiments"]["sql"])
        self.assertGreater(results["data"]["real_examples"], 0)


def _write_plain(path: Path, *, mode: str, count: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {}
    for index in range(count):
        repo = f"https://example.test/{mode}/{index}"
        commit = f"commit-{index}"
        filename = f"app_{index}.py"
        vulnerable_line = f"query = f\"SELECT * FROM users WHERE name = '{{name}}'\""
        source = "\n".join(
            [
                "import sqlite3",
                "",
                f"def helper_{index}(value):",
                "    clean = str(value)",
                "    return clean",
                "",
                "def lookup(name):",
                "    db = sqlite3.connect('users.db')",
                f"    {vulnerable_line}",
                "    return db.execute(query).fetchall()",
                "",
                f"def footer_{index}():",
                f"    return 'done-{index}'",
            ]
        )
        data[repo] = {
            commit: {
                "msg": "Fix SQL injection",
                "files": {
                    filename: {
                        "source": source,
                        "sourceWithComments": source,
                        "sourcecodeafter": source.replace(vulnerable_line, "return db.execute('SELECT 1').fetchall()"),
                        "changes": [
                            {
                                "filename": filename,
                                "badparts": [vulnerable_line],
                                "goodparts": ["return db.execute('SELECT 1').fetchall()"],
                                "diff": "",
                                "add": 1,
                                "remove": 1,
                            }
                        ],
                    }
                },
            }
        }
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
