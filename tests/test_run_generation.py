from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from synvulcommit.llm_generator import GeneratedCommit, GenerationError
from synvulcommit.reviewer import ReviewResult
from synvulcommit.run_generation import main
from synvulcommit.storage import append_jsonl


class RunGenerationTests(unittest.TestCase):
    def test_missing_provider_configuration_fails_before_creating_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            argv = [
                "run_generation.py",
                "--per-cwe",
                "1",
                "--provider",
                "openai_compatible",
                "--output",
                str(output),
            ]
            with patch.object(sys, "argv", argv), patch.dict(os.environ, {}, clear=True):
                exit_code = main()

            output_exists = output.exists()

        self.assertEqual(2, exit_code)
        self.assertFalse(output_exists)

    def test_unfilled_quota_slot_writes_summary_and_returns_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            argv = [
                "run_generation.py",
                "--per-cwe",
                "1",
                "--cwe",
                "sql",
                "--max-attempts",
                "1",
                "--provider",
                "mock",
                "--generation-profile",
                "window_balanced",
                "--output",
                str(output),
                "--no-export",
            ]
            with patch.object(sys, "argv", argv), patch(
                "synvulcommit.run_generation.generate_commit",
                side_effect=GenerationError("forced generation failure"),
            ):
                exit_code = main()

            summary = json.loads((output / "diversity_summary.json").read_text(encoding="utf-8"))
            rejected = [
                json.loads(line)
                for line in (output / "rejected.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]

        self.assertEqual(1, exit_code)
        self.assertEqual(1, summary["coverage"]["sql"]["planned"])
        self.assertEqual(1, summary["coverage"]["sql"]["unfilled"])
        self.assertEqual(1, len(rejected))
        self.assertEqual("window_balanced", rejected[0]["generation_profile"])
        self.assertEqual("window_balanced", rejected[0]["context"]["generation_profile"])

    def test_workers_run_slots_concurrently_and_keep_accepted_ids_unique(self) -> None:
        barrier = threading.Barrier(4)
        active_lock = threading.Lock()
        active = 0
        maximum_active = 0

        def generate(provider: str, spec: object, prompt: str) -> GeneratedCommit:
            del provider, prompt
            nonlocal active, maximum_active
            with active_lock:
                active += 1
                maximum_active = max(maximum_active, active)
            try:
                barrier.wait(timeout=3)
            finally:
                with active_lock:
                    active -= 1
            return _candidate_for_index(getattr(spec, "sample_index"))

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            argv = [
                "run_generation.py",
                "--per-cwe",
                "4",
                "--cwe",
                "sql",
                "--max-attempts",
                "1",
                "--workers",
                "4",
                "--provider",
                "mock",
                "--output",
                str(output),
                "--no-export",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch("synvulcommit.run_generation.generate_commit", side_effect=generate),
                patch("synvulcommit.run_generation.validate_candidate", return_value=_PassingValidation()),
            ):
                exit_code = main()

            records = [
                json.loads(line)
                for line in (output / "samples.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            summary = json.loads((output / "diversity_summary.json").read_text(encoding="utf-8"))

        self.assertEqual(0, exit_code)
        self.assertEqual(4, maximum_active)
        self.assertEqual(4, len(records))
        self.assertEqual(4, len({record["id"] for record in records}))
        self.assertTrue(all(record["review"]["verdict"] == "pass" for record in records))
        self.assertEqual(4, summary["performance"]["workers"])
        self.assertEqual(4, summary["performance"]["attempts"])

    def test_failed_review_retries_same_slot_then_accepts_passing_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            argv = [
                "run_generation.py",
                "--per-cwe",
                "1",
                "--cwe",
                "sql",
                "--max-attempts",
                "2",
                "--provider",
                "mock",
                "--output",
                str(output),
                "--no-export",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch("synvulcommit.run_generation.generate_commit", return_value=_candidate_for_index(0)),
                patch("synvulcommit.run_generation.validate_candidate", return_value=_PassingValidation()),
                patch(
                    "synvulcommit.run_generation.review_candidate",
                    side_effect=[
                        _review_result("fail", fix_correct=False, reason_category="incomplete_fix"),
                        _review_result("pass"),
                    ],
                ) as reviewer,
            ):
                exit_code = main()

            accepted = _read_jsonl(output / "samples.jsonl")
            rejected = _read_jsonl(output / "rejected.jsonl")
            summary = json.loads((output / "diversity_summary.json").read_text(encoding="utf-8"))

        self.assertEqual(0, exit_code)
        self.assertEqual(2, reviewer.call_count)
        self.assertEqual(1, len(accepted))
        self.assertEqual("pass", accepted[0]["review"]["verdict"])
        self.assertEqual(1, len(rejected))
        self.assertEqual("fail", rejected[0]["review"]["verdict"])
        self.assertEqual({"enabled": True, "passed": 1, "rejected": 1, "errors": 0}, summary["review"])

    def test_reviewer_provider_error_leaves_slot_unfilled_without_raw_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            argv = [
                "run_generation.py",
                "--per-cwe",
                "1",
                "--cwe",
                "sql",
                "--max-attempts",
                "1",
                "--provider",
                "mock",
                "--output",
                str(output),
                "--no-export",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch("synvulcommit.run_generation.generate_commit", return_value=_candidate_for_index(0)),
                patch("synvulcommit.run_generation.validate_candidate", return_value=_PassingValidation()),
                patch(
                    "synvulcommit.run_generation.review_candidate",
                    side_effect=GenerationError("https://provider.example/secret-token"),
                ),
            ):
                exit_code = main()

            rejected_text = (output / "rejected.jsonl").read_text(encoding="utf-8")
            rejected = _read_jsonl(output / "rejected.jsonl")
            summary = json.loads((output / "diversity_summary.json").read_text(encoding="utf-8"))

        self.assertEqual(1, exit_code)
        self.assertEqual(1, summary["coverage"]["sql"]["unfilled"])
        self.assertEqual({"enabled": True, "passed": 0, "rejected": 0, "errors": 1}, summary["review"])
        self.assertEqual("error", rejected[0]["review"]["status"])
        self.assertNotIn("provider.example", rejected_text)
        self.assertNotIn("secret-token", rejected_text)

    def test_no_review_skips_reviewer_for_diagnostic_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            argv = [
                "run_generation.py",
                "--per-cwe",
                "1",
                "--cwe",
                "sql",
                "--max-attempts",
                "1",
                "--provider",
                "mock",
                "--output",
                str(output),
                "--no-review",
                "--no-export",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch("synvulcommit.run_generation.generate_commit", return_value=_candidate_for_index(0)),
                patch("synvulcommit.run_generation.validate_candidate", return_value=_PassingValidation()),
                patch("synvulcommit.run_generation.review_candidate") as reviewer,
            ):
                exit_code = main()

            accepted = _read_jsonl(output / "samples.jsonl")

        self.assertEqual(0, exit_code)
        reviewer.assert_not_called()
        self.assertEqual({"required": False, "status": "skipped"}, accepted[0]["review"])

    def test_generation_profile_is_recorded_on_accepted_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            argv = [
                "run_generation.py",
                "--per-cwe",
                "1",
                "--cwe",
                "sql",
                "--max-attempts",
                "1",
                "--provider",
                "mock",
                "--generation-profile",
                "window_balanced",
                "--output",
                str(output),
                "--no-review",
                "--no-export",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch("synvulcommit.run_generation.generate_commit", return_value=_candidate_for_index(0)),
                patch("synvulcommit.run_generation.validate_candidate", return_value=_PassingValidation()),
            ):
                exit_code = main()

            accepted = _read_jsonl(output / "samples.jsonl")
            summary = json.loads((output / "diversity_summary.json").read_text(encoding="utf-8"))

        self.assertEqual(0, exit_code)
        self.assertEqual("window_balanced", accepted[0]["generation_profile"])
        self.assertEqual("window_balanced", accepted[0]["context"]["generation_profile"])
        self.assertNotEqual("single_function", accepted[0]["context"]["structure"])
        self.assertEqual("window_balanced", summary["coverage"]["sql"]["generation_profile"])

    def test_existing_target_is_resumed_without_calling_the_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            output.mkdir()
            append_jsonl(output / "samples.jsonl", _existing_sql_record())
            argv = [
                "run_generation.py",
                "--per-cwe",
                "1",
                "--cwe",
                "sql",
                "--provider",
                "openai_compatible",
                "--output",
                str(output),
                "--no-export",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch("synvulcommit.run_generation.generate_commit") as generate,
                patch.dict(os.environ, {"SYNVUL_API_KEY": "test-key", "SYNVUL_MODEL": "test-model"}),
            ):
                exit_code = main()

            summary = json.loads((output / "diversity_summary.json").read_text(encoding="utf-8"))
            verification_exists = (output / "dataset_verification.json").exists()

        self.assertEqual(0, exit_code)
        generate.assert_not_called()
        self.assertFalse(verification_exists)
        coverage = summary["coverage"]["sql"]
        self.assertEqual(1, coverage["target_accepted"])
        self.assertEqual(1, coverage["existing_accepted"])
        self.assertEqual(0, coverage["planned"])
        self.assertEqual(1, coverage["total_accepted"])
        self.assertTrue(coverage["target_met"])

    def test_normal_export_writes_a_passing_dataset_verification_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            output.mkdir()
            append_jsonl(output / "samples.jsonl", _existing_sql_record())
            argv = [
                "run_generation.py",
                "--per-cwe",
                "1",
                "--cwe",
                "sql",
                "--provider",
                "openai_compatible",
                "--output",
                str(output),
            ]
            with (
                patch.object(sys, "argv", argv),
                patch("synvulcommit.run_generation.generate_commit") as generate,
                patch.dict(os.environ, {"SYNVUL_API_KEY": "test-key", "SYNVUL_MODEL": "test-model"}),
            ):
                exit_code = main()
            report = json.loads((output / "dataset_verification.json").read_text(encoding="utf-8"))

        self.assertEqual(0, exit_code)
        generate.assert_not_called()
        self.assertEqual("pass", report["status"])

    def test_verification_failure_makes_generation_fail_after_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            output.mkdir()
            invalid_record = _existing_sql_record()
            invalid_record.pop("validation")
            append_jsonl(output / "samples.jsonl", invalid_record)
            argv = [
                "run_generation.py",
                "--per-cwe",
                "1",
                "--cwe",
                "sql",
                "--provider",
                "openai_compatible",
                "--output",
                str(output),
            ]
            with (
                patch.object(sys, "argv", argv),
                patch("synvulcommit.run_generation.generate_commit") as generate,
                patch.dict(os.environ, {"SYNVUL_API_KEY": "test-key", "SYNVUL_MODEL": "test-model"}),
            ):
                exit_code = main()
            report = json.loads((output / "dataset_verification.json").read_text(encoding="utf-8"))

        self.assertEqual(1, exit_code)
        generate.assert_not_called()
        self.assertEqual("fail", report["status"])
        self.assertIn("missing_validation", {item["code"] for item in report["errors"]})


def _existing_sql_record() -> dict[str, object]:
    return {
        "id": "CWE-89_sql_000001",
        "cwe": "CWE-89",
        "mode": "sql",
        "context": {
            "cwe_key": "sql",
            "mode": "sql",
            "sample_index": 0,
            "application_type": "Flask",
            "flow_pattern": "direct",
            "structure": "single_function",
            "difficulty": "easy",
        },
        "vulnerable_code": "def query(value):\n    return value\n",
        "fixed_code": "def query(value):\n    return str(value)\n",
        "validation": {
            "passed": True,
            "reasons": [],
            "warnings": [],
            "structural": {"passed": True, "vulnerable_markers": [], "fixed_markers": []},
            "bandit_before": {"available": True, "status": "success", "findings": []},
            "bandit_after": {"available": True, "status": "success", "findings": []},
            "semgrep_before": {"available": True, "status": "success", "findings": []},
            "semgrep_after": {"available": True, "status": "success", "findings": []},
        },
    }


class _PassingValidation:
    passed = True

    def to_dict(self) -> dict[str, object]:
        return {
            "passed": True,
            "reasons": [],
            "warnings": [],
            "structural": {"passed": True, "vulnerable_markers": [], "fixed_markers": []},
            "bandit_before": {"available": True, "status": "success", "findings": []},
            "bandit_after": {"available": True, "status": "success", "findings": []},
            "semgrep_before": {"available": True, "status": "success", "findings": []},
            "semgrep_after": {"available": True, "status": "success", "findings": []},
        }


def _candidate_for_index(index: int) -> GeneratedCommit:
    vulnerable_templates = (
        "def lookup(value):\n    return value + 1\n",
        "def lookup(value):\n    if value:\n        return value\n    return 0\n",
        "def lookup(value):\n    total = 0\n    for item in range(value):\n        total += item\n    return total\n",
        "def lookup(value):\n    try:\n        return value / 2\n    except TypeError:\n        return 0\n",
    )
    fixed_templates = (
        "def lookup(value):\n    return str(value + 1)\n",
        "def lookup(value):\n    if value:\n        return str(value)\n    return \"0\"\n",
        "def lookup(value):\n    total = 0\n    for item in range(value):\n        total += item\n    return str(total)\n",
        "def lookup(value):\n    try:\n        return str(value / 2)\n    except TypeError:\n        return \"0\"\n",
    )
    vulnerable = vulnerable_templates[index]
    fixed = fixed_templates[index]
    return GeneratedCommit(
        commit_message="Fix generated sample",
        filename=f"app_{index}.py",
        vulnerable_code=vulnerable,
        fixed_code=fixed,
        diff="--- a/app.py\n+++ b/app.py\n",
        badparts=[vulnerable.splitlines()[-1]],
        goodparts=[fixed.splitlines()[-1]],
        provider="mock",
        raw_response={},
    )


def _review_result(
    verdict: str,
    *,
    cwe_correct: bool = True,
    fix_correct: bool = True,
    context_correct: bool = True,
    runtime_plausible: bool = True,
    reason_category: str = "none",
) -> ReviewResult:
    return ReviewResult(
        verdict=verdict,
        cwe_correct=cwe_correct,
        fix_correct=fix_correct,
        context_correct=context_correct,
        runtime_plausible=runtime_plausible,
        reason_category=reason_category,
        provider="mock",
        model=None,
    )


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
