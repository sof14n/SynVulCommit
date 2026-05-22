from __future__ import annotations

import unittest

from synvulcommit.diversity import DiversityIndex
from synvulcommit.run_generation import build_generation_plan, count_existing_by_mode
from synvulcommit.storage import next_sample_id


class ResumeGenerationTests(unittest.TestCase):
    def test_target_mode_plans_only_missing_sql_samples(self) -> None:
        existing = [_record("sql", "CWE-89", index) for index in range(1, 4)]

        plan = build_generation_plan(
            per_cwe=1,
            target_per_cwe=5,
            existing_records=existing,
            seed=1337,
            cwe_filters=["sql"],
        )

        self.assertTrue(plan["matched"])
        self.assertEqual(2, len(plan["specs"]))
        self.assertTrue(all(spec.mode == "sql" for spec in plan["specs"]))
        self.assertEqual(3, plan["stats"]["sql"]["existing"])
        self.assertEqual(2, plan["stats"]["sql"]["planned"])
        self.assertEqual(2, plan["stats"]["sql"]["remaining"])

    def test_target_mode_skips_completed_cwe(self) -> None:
        existing = [_record("sql", "CWE-89", index) for index in range(1, 6)]

        plan = build_generation_plan(
            per_cwe=1,
            target_per_cwe=5,
            existing_records=existing,
            seed=1337,
            cwe_filters=["sql"],
        )

        self.assertTrue(plan["matched"])
        self.assertEqual([], plan["specs"])
        self.assertEqual(5, plan["stats"]["sql"]["existing"])
        self.assertEqual(0, plan["stats"]["sql"]["planned"])

    def test_unknown_cwe_filter_reports_no_match(self) -> None:
        plan = build_generation_plan(
            per_cwe=1,
            target_per_cwe=5,
            existing_records=[],
            seed=1337,
            cwe_filters=["not-a-cwe"],
        )

        self.assertFalse(plan["matched"])
        self.assertEqual([], plan["specs"])

    def test_existing_counts_use_mode(self) -> None:
        counts = count_existing_by_mode(
            [
                {"mode": "sql"},
                {"context": {"mode": "sql"}},
                {"mode": "xss"},
            ]
        )

        self.assertEqual({"sql": 2, "xss": 1}, counts)

    def test_next_sample_id_uses_max_suffix_not_count(self) -> None:
        records = [
            {"id": "CWE-89_sql_000001"},
            {"id": "CWE-89_sql_000003"},
            {"id": "CWE-79_xss_000010"},
        ]

        self.assertEqual("CWE-89_sql_000004", next_sample_id(records, "CWE-89", "sql"))

    def test_loaded_existing_records_reject_duplicate_code(self) -> None:
        existing = _record("sql", "CWE-89", 1)
        duplicate = dict(existing)
        duplicate["id"] = "CWE-89_sql_000002"
        diversity = DiversityIndex()

        diversity.load_existing([existing])
        accepted, reason = diversity.accepts(duplicate)

        self.assertFalse(accepted)
        self.assertEqual("duplicate code pair hash", reason)
        self.assertEqual("exact_code_pair", diversity.last_rejection["check"])
        self.assertEqual("CWE-89_sql_000001", diversity.last_rejection["matched_id"])


def _record(mode: str, cwe: str, index: int) -> dict[str, object]:
    return {
        "id": f"{cwe}_{mode}_{index:06d}",
        "cwe": cwe,
        "mode": mode,
        "vulnerable_code": f"def sample_{index}():\n    return {index}\n",
        "context": {"mode": mode},
    }


if __name__ == "__main__":
    unittest.main()
