from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from synvulcommit.diversity import DiversityIndex, write_diversity_summary
from synvulcommit.storage import append_jsonl


class DiversityIndexTests(unittest.TestCase):
    def test_exact_code_pair_duplicate_is_rejected_with_match_detail(self) -> None:
        index = DiversityIndex()
        first = _record("sample-1", _simple_code("name", "total", "1"), _simple_fixed("name", "total", "1"))
        duplicate = dict(first, id="sample-2")

        self.assertAccepted(index, first)
        accepted, reason = index.accepts(duplicate)

        self.assertFalse(accepted)
        self.assertEqual("duplicate code pair hash", reason)
        self.assertEqual("exact_code_pair", index.last_rejection["check"])
        self.assertEqual("sample-1", index.last_rejection["matched_id"])
        self.assertIn("fingerprint", index.last_rejection)

    def test_renamed_variable_duplicate_is_rejected_by_normalized_ast(self) -> None:
        index = DiversityIndex()
        first = _record("sample-1", _simple_code("name", "total", "1"), _simple_fixed("name", "total", "1"))
        renamed = _record("sample-2", _simple_code("username", "score", "1"), _simple_fixed("username", "score", "1"))

        self.assertAccepted(index, first)
        accepted, reason = index.accepts(renamed)

        self.assertFalse(accepted)
        self.assertEqual("duplicate normalized AST fingerprint", reason)
        self.assertEqual("normalized_ast", index.last_rejection["check"])
        self.assertEqual("sample-1", index.last_rejection["matched_id"])

    def test_literal_only_variation_is_rejected_by_normalized_ast(self) -> None:
        index = DiversityIndex()
        first = _record("sample-1", _simple_code("name", "total", "1"), _simple_fixed("name", "total", "1"))
        literal_variant = _record("sample-2", _simple_code("name", "total", "99"), _simple_fixed("name", "total", "100"))

        self.assertAccepted(index, first)
        accepted, reason = index.accepts(literal_variant)

        self.assertFalse(accepted)
        self.assertEqual("duplicate normalized AST fingerprint", reason)
        self.assertEqual("normalized_ast", index.last_rejection["check"])

    def test_near_duplicate_above_threshold_is_rejected(self) -> None:
        index = DiversityIndex()
        first = _record("sample-1", _long_code(extra_line=""), _long_fixed(extra_line=""))
        near_duplicate = _record("sample-2", _long_code(extra_line="    marker = step_17\n"), _long_fixed(extra_line="    marker = step_17\n"))

        self.assertAccepted(index, first)
        accepted, reason = index.accepts(near_duplicate)

        self.assertFalse(accepted)
        self.assertTrue(reason.startswith("near-duplicate token shingles similarity"))
        self.assertEqual("near_duplicate", index.last_rejection["check"])
        self.assertGreaterEqual(index.last_rejection["similarity"], 0.90)

    def test_distinct_sample_below_threshold_is_accepted(self) -> None:
        index = DiversityIndex()
        first = _record("sample-1", _simple_code("name", "total", "1"), _simple_fixed("name", "total", "1"))
        distinct = _record(
            "sample-2",
            "import subprocess\n\ndef ping(host):\n    return subprocess.run('ping ' + host, shell=True)\n",
            "import subprocess\n\ndef ping(host):\n    return subprocess.run(['ping', host], shell=False)\n",
        )

        self.assertAccepted(index, first)
        self.assertAccepted(index, distinct)

    def test_summary_tracks_required_distributions(self) -> None:
        index = DiversityIndex()
        self.assertAccepted(index, _record("sample-1", _simple_code("name", "total", "1"), _simple_fixed("name", "total", "1")))
        summary = index.summary()

        self.assertEqual(1, summary["total_records"])
        self.assertEqual({"CWE-89": 1}, summary["distributions"]["cwe"])
        self.assertEqual({"Flask": 1}, summary["distributions"]["application_type"])
        self.assertEqual({"direct": 1}, summary["distributions"]["flow_pattern"])
        self.assertEqual({"easy": 1}, summary["distributions"]["difficulty"])
        self.assertEqual({"single_function": 1}, summary["distributions"]["structure"])

    def test_rejection_detail_is_jsonl_serializable(self) -> None:
        index = DiversityIndex()
        first = _record("sample-1", _simple_code("name", "total", "1"), _simple_fixed("name", "total", "1"))
        duplicate = dict(first, id="sample-2")
        self.assertAccepted(index, first)
        accepted, reason = index.accepts(duplicate)
        self.assertFalse(accepted)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rejected.jsonl"
            summary_path = Path(tmp) / "diversity_summary.json"
            append_jsonl(path, {**duplicate, "reject_reason": [reason], "diversity_rejection": index.last_rejection})
            write_diversity_summary(index.summary(), summary_path)
            rejected = json.loads(path.read_text(encoding="utf-8"))
            summary = json.loads(summary_path.read_text(encoding="utf-8"))

        self.assertEqual("sample-1", rejected["diversity_rejection"]["matched_id"])
        self.assertIn("exact_code_pair", summary["duplicate_rejections"])

    def assertAccepted(self, index: DiversityIndex, record: dict[str, object]) -> None:
        accepted, reason = index.accepts(record)
        self.assertTrue(accepted, reason)


def _record(sample_id: str, vulnerable_code: str, fixed_code: str) -> dict[str, object]:
    return {
        "id": sample_id,
        "cwe": "CWE-89",
        "mode": "sql",
        "context": {
            "application_type": "Flask",
            "flow_pattern": "direct",
            "difficulty": "easy",
            "structure": "single_function",
        },
        "vulnerable_code": vulnerable_code,
        "fixed_code": fixed_code,
    }


def _simple_code(argument: str, local: str, literal: str) -> str:
    return f"def lookup({argument}):\n    {local} = {argument} + {literal}\n    return {local}\n"


def _simple_fixed(argument: str, local: str, literal: str) -> str:
    return f"def lookup({argument}):\n    {local} = {argument} + {literal}\n    return str({local})\n"


def _long_code(extra_line: str) -> str:
    operators = ["+", "-", "*", "/", "//", "%", "**", "<<", ">>", "|", "&", "^"]
    lines = ["def lookup(value):", "    result = value"]
    for index in range(80):
        lines.append(f"    result = result {operators[index % len(operators)]} value")
    if extra_line:
        lines.append(extra_line.rstrip())
    lines.append("    return result")
    return "\n".join(lines) + "\n"


def _long_fixed(extra_line: str) -> str:
    operators = ["+", "-", "*", "/", "//", "%", "**", "<<", ">>", "|", "&", "^"]
    lines = ["def lookup(value):", "    result = value"]
    for index in range(80):
        lines.append(f"    result = result {operators[index % len(operators)]} value")
    if extra_line:
        lines.append(extra_line.rstrip())
    lines.append("    return str(result)")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    unittest.main()
