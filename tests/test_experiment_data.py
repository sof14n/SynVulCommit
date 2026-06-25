from __future__ import annotations

import unittest

from synvulcommit.experiment_data import (
    CANONICAL_MODES,
    CommitRecord,
    select_balanced_synthetic,
    cap_windows,
    select_real_cap,
    split_commits,
    token_windows,
)


def record(mode: str, number: int, dataset: str = "synthetic", **context: str) -> CommitRecord:
    values = {
        "application_type": "api" if number % 2 else "script",
        "flow_pattern": "direct" if number % 2 else "indirect",
        "difficulty": "easy" if number % 2 else "hard",
        "structure": "single_function" if number % 2 else "multi_function",
    }
    values.update(context)
    return CommitRecord(
        dataset=dataset,
        mode=mode,
        commit_id=f"{mode}-{number}",
        repo="repo",
        filename=f"f{number}.py",
        source="value = request.args['q']\ncursor.execute('SELECT ' + value)\n",
        fixed_source="cursor.execute('SELECT ?', (value,))\n",
        badparts=("cursor.execute('SELECT ' + value)",),
        goodparts=("cursor.execute('SELECT ?', (value,))",),
        context=values,
    )


class ExperimentDataTests(unittest.TestCase):
    def test_balanced_selection_is_deterministic_and_has_requested_count(self) -> None:
        records = [record(mode, number) for mode in CANONICAL_MODES for number in range(12)]
        first = select_balanced_synthetic(records, 8, 42)
        second = select_balanced_synthetic(records, 8, 42)
        self.assertEqual([item.commit_id for item in first], [item.commit_id for item in second])
        for mode in CANONICAL_MODES:
            selected = [item for item in first if item.mode == mode]
            self.assertEqual(8, len(selected))
            applications = {item.context["application_type"] for item in selected}
            self.assertEqual({"api", "script"}, applications)

    def test_real_cap_and_split_are_commit_grouped(self) -> None:
        records = [record("sql", number, "real") for number in range(4)]
        # The second file belongs to the same real commit and must retain its split.
        records.append(record("sql", 0, "real", structure="class_based"))
        selected = select_real_cap(records, 3, 5)
        self.assertEqual(3, len({item.group_id for item in selected}))
        assignments = split_commits(selected, 5)
        self.assertEqual(len({item.group_id for item in selected}), len(assignments))
        self.assertEqual(assignments[records[0].group_id], assignments[records[-1].group_id])
        grouped = {split: set() for split in ("train", "validation", "test")}
        for group_id, split in assignments.items():
            grouped[split].add(group_id)
        self.assertFalse(grouped["train"] & grouped["validation"])
        self.assertFalse(grouped["train"] & grouped["test"])
        self.assertFalse(grouped["validation"] & grouped["test"])

    def test_window_labels_follow_changed_vulnerable_parts(self) -> None:
        sample = record("sql", 1)
        windows = token_windows(sample, window_size=200, stride=5)
        self.assertEqual(1, len(windows))
        self.assertEqual(1, windows[0]["label"])
        clean = CommitRecord(**{**sample.__dict__, "badparts": ("not present",)})
        self.assertEqual(0, token_windows(clean, window_size=200, stride=5)[0]["label"])

    def test_window_cap_is_deterministic_and_preserves_both_labels(self) -> None:
        windows = [
            {"label": label, "group_id": "g", "filename": "f.py", "tokens": [str(index)]}
            for label in (0, 1) for index in range(10)
        ]
        first = cap_windows(windows, 3, 3, 7)
        second = cap_windows(windows, 3, 3, 7)
        self.assertEqual(first, second)
        self.assertEqual(3, sum(item["label"] for item in first))
        self.assertEqual(3, sum(not item["label"] for item in first))


if __name__ == "__main__":
    unittest.main()
