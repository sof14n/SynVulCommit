from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from synvulcommit.revalidate_dataset import revalidate_output
from synvulcommit.spec_sampler import build_coverage_plan
from synvulcommit.storage import next_sample_id, read_jsonl


class RevalidateDatasetTests(unittest.TestCase):
    def test_revalidation_preserves_source_quarantines_failures_and_leaves_gap_safe_ids(self) -> None:
        source_records = [_record(1, "good_one.py"), _record(2, "bad.py"), _record(3, "good_three.py")]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            source_samples = source / "samples.jsonl"
            source_text = "".join(json.dumps(record) + "\n" for record in source_records)
            source_samples.write_text(source_text, encoding="utf-8")
            output = root / "output"
            with patch("synvulcommit.revalidate_dataset.validate_candidate", side_effect=_validate):
                summary = revalidate_output(source, output, require_tools=True, workers=2)

            retained = read_jsonl(output / "samples.jsonl")
            quarantined = read_jsonl(output / "rejected.jsonl")
            verification = json.loads((output / "dataset_verification.json").read_text(encoding="utf-8"))
            plan = build_coverage_plan(4, 1337, retained, ["sql"])

            self.assertEqual(source_text, source_samples.read_text(encoding="utf-8"))
            self.assertEqual(3, summary["source_accepted"])
            self.assertEqual(2, summary["retained"])
            self.assertEqual(1, summary["quarantined"])
            self.assertEqual("pass", summary["verification_status"])
            self.assertEqual(["CWE-89_sql_000001", "CWE-89_sql_000003"], [record["id"] for record in retained])
            self.assertEqual("quarantined", quarantined[0]["revalidation"]["status"])
            self.assertEqual("validation", quarantined[0]["revalidation"]["reason_categories"][0])
            self.assertEqual("CWE-89_sql_000004", next_sample_id(retained, "CWE-89", "sql"))
            self.assertEqual(2, len(plan.specs))
            self.assertEqual("pass", verification["status"])


class _Validation:
    def __init__(self, passed: bool, reasons: list[str]) -> None:
        self.passed = passed
        self.reasons = reasons

    def to_dict(self) -> dict[str, object]:
        return {
            "passed": self.passed,
            "reasons": self.reasons,
            "warnings": [],
            "structural": {"passed": self.passed, "vulnerable_markers": ["dynamic SQL"], "fixed_markers": ["bound SQL"]},
            "bandit_before": {"available": True, "status": "success", "findings": []},
            "bandit_after": {"available": True, "status": "success", "findings": []},
            "semgrep_before": {"available": True, "status": "success", "findings": [{"check_id": "synvul.cwe-89.sql-injection"}]},
            "semgrep_after": {"available": True, "status": "success", "findings": []},
        }


def _validate(spec: object, candidate: object, rules_dir: Path, temp_root: Path, require_tools: bool) -> _Validation:
    del spec, rules_dir, temp_root, require_tools
    if getattr(candidate, "filename") == "bad.py":
        return _Validation(False, ["fixed code does not use parameterized SQL"])
    return _Validation(True, [])


def _record(index: int, filename: str) -> dict[str, object]:
    vulnerable_code = "def lookup(value):\n    return value\n"
    fixed_code = "def lookup(value):\n    return str(value)\n"
    if index == 3:
        vulnerable_code = "def lookup(value):\n    if value:\n        return value\n    return ''\n"
        fixed_code = "def lookup(value):\n    if value:\n        return str(value)\n    return ''\n"
    return {
        "id": f"CWE-89_sql_{index:06d}",
        "cwe": "CWE-89",
        "cwe_name": "SQL Injection",
        "mode": "sql",
        "context": {
            "cwe_key": "sql",
            "cwe": "CWE-89",
            "cwe_name": "SQL Injection",
            "mode": "sql",
            "application_type": "Flask",
            "flow_pattern": "direct",
            "difficulty": "easy",
            "structure": "single_function",
            "sample_index": index,
        },
        "commit_message": "Fix SQL injection",
        "filename": filename,
        "vulnerable_code": vulnerable_code,
        "fixed_code": fixed_code,
        "diff": "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-return value\n+return str(value)\n",
        "badparts": ["return value"],
        "goodparts": ["return str(value)"],
        "provider": "mock",
        "validation": {},
        "review": {
            "required": True,
            "status": "completed",
            "verdict": "pass",
            "cwe_correct": True,
            "fix_correct": True,
            "context_correct": True,
            "runtime_plausible": True,
            "reason_category": "none",
            "provider": "mock",
            "model": None,
        },
    }


if __name__ == "__main__":
    unittest.main()
