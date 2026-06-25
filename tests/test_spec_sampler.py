from __future__ import annotations

from collections import Counter
import unittest

from synvulcommit.spec_sampler import FLOW_PATTERNS_BY_STRUCTURE, build_coverage_plan


class CoveragePlanTests(unittest.TestCase):
    def test_plan_is_deterministic_for_identical_inputs(self) -> None:
        first = build_coverage_plan(12, 1337, [], ["sql"])
        second = build_coverage_plan(12, 1337, [], ["sql"])

        self.assertEqual([spec.to_dict() for spec in first.specs], [spec.to_dict() for spec in second.specs])

    def test_new_slots_are_marginally_balanced(self) -> None:
        plan = build_coverage_plan(12, 1337, [], ["sql"])
        counts = Counter(spec.application_type for spec in plan.specs)
        flow_counts = Counter(spec.flow_pattern for spec in plan.specs)
        structure_counts = Counter(spec.structure for spec in plan.specs)
        difficulty_counts = Counter(spec.difficulty for spec in plan.specs)

        for distribution in (counts, flow_counts, structure_counts, difficulty_counts):
            self.assertLessEqual(max(distribution.values()) - min(distribution.values()), 1)

    def test_planner_excludes_flow_structure_pairs_that_cannot_meet_the_contract(self) -> None:
        plan = build_coverage_plan(72, 1337, [], ["sql"])
        compatible = plan.coverage_by_mode["sql"].compatible_tuples

        self.assertEqual(72, len(compatible))
        self.assertNotIn(("Flask", "complex", "single_function", "easy"), compatible)
        self.assertNotIn(("Flask", "indirect", "single_function", "easy"), compatible)
        self.assertNotIn(("Flask", "direct", "multi_function", "easy"), compatible)
        for spec in plan.specs:
            self.assertIn(spec.flow_pattern, FLOW_PATTERNS_BY_STRUCTURE[spec.structure])

    def test_existing_records_steer_new_slots_to_underrepresented_contexts(self) -> None:
        existing = [
            {
                "cwe": "CWE-89",
                "mode": "sql",
                "context": {
                    "mode": "sql",
                    "sample_index": index,
                    "application_type": "Flask",
                    "flow_pattern": "direct",
                    "structure": "single_function",
                    "difficulty": "easy",
                },
            }
            for index in range(5)
        ]

        plan = build_coverage_plan(6, 1337, existing, ["sql"])

        self.assertEqual(1, len(plan.specs))
        self.assertNotEqual("Flask", plan.specs[0].application_type)
        self.assertNotEqual("direct", plan.specs[0].flow_pattern)

    def test_existing_records_reduce_the_remaining_target(self) -> None:
        existing = [_sql_record(index) for index in range(2)]

        plan = build_coverage_plan(3, 1337, existing, ["sql"])
        summary = plan.summary()["sql"]

        self.assertEqual(1, len(plan.specs))
        self.assertEqual(3, summary["target_accepted"])
        self.assertEqual(2, summary["existing_accepted"])
        self.assertEqual(1, summary["planned"])
        self.assertFalse(summary["target_met"])

    def test_target_already_met_plans_no_new_slots(self) -> None:
        existing = [_sql_record(index) for index in range(2)]

        plan = build_coverage_plan(2, 1337, existing, ["sql"])
        summary = plan.summary()["sql"]

        self.assertEqual([], plan.specs)
        self.assertEqual(0, summary["planned"])
        self.assertEqual(2, summary["total_accepted"])
        self.assertTrue(summary["target_met"])
        self.assertFalse(plan.has_unfilled)

    def test_context_cwe_key_is_enough_to_resume_legacy_record(self) -> None:
        record = _sql_record(0)
        record.pop("cwe")
        record.pop("mode")
        record["context"].pop("mode")

        plan = build_coverage_plan(1, 1337, [record], ["sql"])
        summary = plan.summary()["sql"]

        self.assertEqual([], plan.specs)
        self.assertEqual(1, summary["existing_accepted"])
        self.assertEqual({"Flask": 1}, {key: value for key, value in summary["distributions"]["application_type"].items() if value})

    def test_unknown_cwe_filter_reports_no_match(self) -> None:
        plan = build_coverage_plan(1, 1337, [], ["not-a-cwe"])

        self.assertFalse(plan.matched)
        self.assertEqual([], plan.specs)


def _sql_record(index: int) -> dict[str, object]:
    return {
        "id": f"CWE-89_sql_{index + 1:06d}",
        "cwe": "CWE-89",
        "mode": "sql",
        "context": {
            "cwe_key": "sql",
            "mode": "sql",
            "sample_index": index,
            "application_type": "Flask",
            "flow_pattern": "direct",
            "structure": "single_function",
            "difficulty": "easy",
        },
    }
