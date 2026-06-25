from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from synvulcommit.export_vudenc import export_records
from synvulcommit.verify_dataset import main, verify_dataset


class DatasetVerificationTests(unittest.TestCase):
    def test_clean_dataset_reports_counts_validation_and_rejections(self) -> None:
        accepted = [_record("CWE-89_sql_000001")]
        rejected = [
            {
                "context": {"cwe_key": "sql", "mode": "sql"},
                "validation": {"reasons": ["fixed code does not use parameterized SQL"]},
                "reject_reason": ["fixed code does not use parameterized SQL"],
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "vudenc"
            export_records(accepted, out_dir)
            report = verify_dataset(accepted, rejected, out_dir)

        self.assertEqual("pass", report["status"])
        self.assertEqual(1, report["accepted"]["total"])
        sql = report["accepted"]["by_cwe"]["sql"]
        self.assertEqual(1, sql["accepted"])
        self.assertEqual({"Flask": 1}, sql["context"]["application_type"])
        self.assertEqual({"Flask|direct|single_function|easy": 1}, sql["context_tuples"])
        self.assertEqual(0, report["duplicates"]["accepted"]["policy_ordered"]["exact_code_pair"]["count"])
        self.assertEqual(1, report["validation"]["accepted"]["passed"])
        self.assertEqual(1, report["review"]["accepted"]["legacy_missing"])
        self.assertEqual(1, report["rejections"]["by_category"]["structural_validation"])
        self.assertTrue(report["export_integrity"]["passed"])

    def test_reviewer_required_accepted_record_must_be_a_complete_pass(self) -> None:
        accepted = _record("CWE-89_sql_000001")
        accepted["review"] = _passing_review()
        rejected = {
            "context": {"cwe_key": "sql", "mode": "sql"},
            "validation": accepted["validation"],
            "review": {**_passing_review(), "verdict": "fail", "fix_correct": False, "reason_category": "incomplete_fix"},
            "reject_reason": ["reviewer rejected candidate: fail/incomplete_fix"],
        }
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "vudenc"
            export_records([accepted], out_dir)
            report = verify_dataset([accepted], [rejected], out_dir)

        self.assertEqual("pass", report["status"])
        self.assertEqual(1, report["review"]["accepted"]["required"])
        self.assertEqual(1, report["review"]["accepted"]["passed"])
        self.assertEqual(1, report["review"]["rejected"]["total"])
        self.assertEqual({"fail": 1}, report["review"]["rejected"]["verdict"])
        self.assertEqual(1, report["rejections"]["by_category"]["reviewer"])

        accepted["review"] = {**_passing_review(), "fix_correct": False}
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "vudenc"
            export_records([accepted], out_dir)
            tampered_report = verify_dataset([accepted], [], out_dir)

        self.assertEqual("fail", tampered_report["status"])
        self.assertEqual(1, tampered_report["review"]["accepted"]["failed"])
        self.assertIn("review_not_passed", {item["code"] for item in tampered_report["errors"]})

    def test_duplicate_policy_reports_exact_ast_and_near_duplicates(self) -> None:
        first = _record("CWE-89_sql_000001", _simple_code("name", "total", "1"), _simple_fixed("name", "total", "1"))
        exact = dict(first, id="CWE-89_sql_000002")
        ast_duplicate = _record(
            "CWE-89_sql_000003",
            _simple_code("username", "score", "99"),
            _simple_fixed("username", "score", "100"),
        )
        long_first = _record("CWE-89_sql_000004", _long_code(""), _long_fixed(""))
        near_duplicate = _record(
            "CWE-89_sql_000005",
            _long_code("    marker = step_17\n"),
            _long_fixed("    marker = step_17\n"),
        )
        records = [first, exact, ast_duplicate, long_first, near_duplicate]
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "vudenc"
            export_records(records, out_dir)
            report = verify_dataset(records, [], out_dir)

        policy = report["duplicates"]["accepted"]["policy_ordered"]
        self.assertEqual("fail", report["status"])
        self.assertEqual(1, policy["exact_code_pair"]["count"])
        self.assertEqual(1, policy["normalized_ast"]["count"])
        self.assertEqual(1, policy["near_duplicate"]["count"])
        self.assertEqual(0.2, policy["near_duplicate"]["rate"])

    def test_validation_warnings_are_non_fatal_but_missing_or_failed_validation_is_not(self) -> None:
        warning_record = _record("CWE-89_sql_000001", warnings=["Semgrep was unavailable"])
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "vudenc"
            export_records([warning_record], out_dir)
            warning_report = verify_dataset([warning_record], [], out_dir)

        missing_record = _record("CWE-89_sql_000002")
        missing_record.pop("validation")
        failed_record = _record("CWE-89_sql_000003")
        failed_record["validation"] = {
            "passed": False,
            "reasons": ["structural check failed"],
            "warnings": [],
            "structural": {"passed": False},
        }
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "vudenc"
            export_records([missing_record, failed_record], out_dir)
            failed_report = verify_dataset([missing_record, failed_record], [], out_dir)

        self.assertEqual("pass", warning_report["status"])
        self.assertEqual(1, warning_report["validation"]["accepted"]["records_with_warnings"])
        self.assertEqual("fail", failed_report["status"])
        self.assertEqual(1, failed_report["validation"]["accepted"]["missing"])
        self.assertEqual(1, failed_report["validation"]["accepted"]["failed"])
        self.assertIn("missing_validation", {item["code"] for item in failed_report["errors"]})
        self.assertIn("failed_validation", {item["code"] for item in failed_report["errors"]})

    def test_post_fix_synvul_semgrep_finding_fails_verification(self) -> None:
        record = _record("CWE-89_sql_000001")
        record["validation"]["semgrep_after"] = {
            "available": True,
            "status": "success",
            "findings": [{"check_id": "synvul.cwe-352.csrf-disabled"}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "vudenc"
            export_records([record], out_dir)
            report = verify_dataset([record], [], out_dir)

        self.assertEqual("fail", report["status"])
        self.assertEqual({"synvul.cwe-352.csrf-disabled": 1}, report["validation"]["accepted"]["post_fix_synvul_rule_ids"])
        self.assertIn("post_fix_synvul_semgrep_finding", {item["code"] for item in report["errors"]})

    def test_structurally_verified_xss_escape_allows_helper_only_after_finding(self) -> None:
        record = _record("CWE-79_xss_000001")
        record["cwe"] = "CWE-79"
        record["cwe_name"] = "Cross-Site Scripting"
        record["mode"] = "xss"
        record["context"]["cwe_key"] = "xss"
        record["context"]["cwe"] = "CWE-79"
        record["context"]["mode"] = "xss"
        record["validation"]["semgrep_after"] = {
            "available": True,
            "status": "success",
            "findings": [{"check_id": "synvul.cwe-79.xss-helper"}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "vudenc"
            export_records([record], out_dir)
            report = verify_dataset([record], [], out_dir)

        self.assertEqual("pass", report["status"])
        self.assertEqual({}, report["validation"]["accepted"]["post_fix_synvul_rule_ids"])

    def test_rejection_categories_do_not_copy_unsafe_details(self) -> None:
        rejected = [
            {"context": {"cwe_key": "sql"}, "reject_reason": ["provider request failed: C:\\Users\\Lenovo\\secret-token"]},
            {"context": {"cwe_key": "sql"}, "validation": {"reasons": ["structural check failed"]}},
            {"context": {"cwe_key": "sql"}, "validation": {"reasons": ["Semgrep failed to run"]}},
            {"context": {"cwe_key": "sql"}, "validation": {"reasons": ["candidate has no vulnerable badparts for VUDENC export"]}},
            {
                "context": {"cwe_key": "sql"},
                "diversity_rejection": {"check": "near_duplicate", "reason": "C:\\Users\\Lenovo\\secret-token"},
            },
        ]
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "vudenc"
            export_records([], out_dir)
            report = verify_dataset([], rejected, out_dir)

        categories = report["rejections"]["by_category"]
        self.assertEqual(1, categories["generation"])
        self.assertEqual(1, categories["structural_validation"])
        self.assertEqual(1, categories["analyzer_tool"])
        self.assertEqual(1, categories["vudenc_parts"])
        self.assertEqual(1, categories["diversity"])
        self.assertEqual({"near_duplicate": 1}, report["rejections"]["diversity_checks"])
        self.assertEqual({"unknown": 5}, report["rejections"]["context"]["application_type"])
        self.assertNotIn("secret-token", json.dumps(report))
        self.assertNotIn("C:\\Users", json.dumps(report))

    def test_tampered_export_fails_integrity_checks_and_cli(self) -> None:
        record = _record("CWE-89_sql_000001")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "samples.jsonl"
            rejected_path = root / "rejected.jsonl"
            input_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            rejected_path.write_text("", encoding="utf-8")
            out_dir = root / "vudenc"
            export_records([record], out_dir)
            plain_path = out_dir / "plain_sql"
            plain = json.loads(plain_path.read_text(encoding="utf-8"))
            plain["synvulcommit/sql"]["CWE-89_sql_000001"]["files"]["app.py"]["source"] = "tampered\n"
            plain_path.write_text(json.dumps(plain), encoding="utf-8")
            (out_dir / "metadata.jsonl").write_text("", encoding="utf-8")
            (out_dir / "plain_unknown").write_text("{}", encoding="utf-8")
            report = verify_dataset([record], [], out_dir)
            argv = ["verify_dataset.py", "--input", str(input_path)]
            with patch.object(sys, "argv", argv):
                exit_code = main()
            cli_report = json.loads((root / "dataset_verification.json").read_text(encoding="utf-8"))

        codes = {item["code"] for item in report["export_integrity"]["errors"]}
        self.assertEqual("fail", report["status"])
        self.assertIn("plain_payload_mismatch", codes)
        self.assertIn("metadata_payload_mismatch", codes)
        self.assertIn("unexpected_plain_file", codes)
        self.assertEqual(1, exit_code)
        self.assertEqual("fail", cli_report["status"])


def _record(
    sample_id: str,
    vulnerable_code: str = "def lookup(value):\n    return value\n",
    fixed_code: str = "def lookup(value):\n    return str(value)\n",
    warnings: list[str] | None = None,
) -> dict[str, object]:
    return {
        "id": sample_id,
        "cwe": "CWE-89",
        "cwe_name": "SQL Injection",
        "mode": "sql",
        "context": {
            "cwe_key": "sql",
            "cwe": "CWE-89",
            "mode": "sql",
            "application_type": "Flask",
            "flow_pattern": "direct",
            "difficulty": "easy",
            "structure": "single_function",
            "sample_index": int(sample_id[-1]),
        },
        "commit_message": "Fix SQL injection",
        "filename": "app.py",
        "vulnerable_code": vulnerable_code,
        "fixed_code": fixed_code,
        "diff": "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-return value\n+return str(value)\n",
        "badparts": ["return value"],
        "goodparts": ["return str(value)"],
        "provider": "openai_compatible",
        "validation": {
            "passed": True,
            "reasons": [],
            "warnings": warnings or [],
            "structural": {"passed": True, "vulnerable_markers": ["dynamic SQL"], "fixed_markers": ["bound SQL"]},
            "bandit_before": {"available": True, "status": "success", "findings": [{"test_id": "B608"}]},
            "bandit_after": {"available": True, "status": "success", "findings": []},
            "semgrep_before": {"available": True, "status": "success", "findings": [{"check_id": "synvul.cwe-89.sql-injection"}]},
            "semgrep_after": {"available": True, "status": "success", "findings": []},
        },
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
    return _long_code(extra_line).replace("return result", "return str(result)")


def _passing_review() -> dict[str, object]:
    return {
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
    }
