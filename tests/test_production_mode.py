from __future__ import annotations

import unittest
from types import SimpleNamespace

from synvulcommit.run_generation import _build_record, validate_production_settings
from synvulcommit.validator import _run_command


class ProductionModeTests(unittest.TestCase):
    def test_production_refuses_mock_provider(self) -> None:
        error = validate_production_settings(provider="mock", require_tools=True, production=True)

        self.assertIsNotNone(error)
        self.assertIn("--provider mock", error or "")
        self.assertIn("--provider openai_compatible", error or "")

    def test_production_requires_strict_validation_tools(self) -> None:
        error = validate_production_settings(provider="local_http", require_tools=False, production=True)

        self.assertIsNotNone(error)
        self.assertIn("--require-tools", error or "")
        self.assertIn("Bandit", error or "")
        self.assertIn("Semgrep", error or "")

    def test_non_production_keeps_demo_settings_available(self) -> None:
        self.assertIsNone(validate_production_settings(provider="mock", require_tools=False, production=False))

    def test_record_includes_provider_model_metadata(self) -> None:
        spec = SimpleNamespace(
            cwe="CWE-78",
            cwe_name="Command Injection",
            mode="command_injection",
            to_dict=lambda: {"cwe": "CWE-78", "mode": "command_injection"},
        )
        candidate = SimpleNamespace(
            commit_message="Fix command injection",
            filename="app.py",
            vulnerable_code="import os\nos.system(user_input)\n",
            fixed_code="import subprocess\nsubprocess.run(['echo', user_input], shell=False)\n",
            diff="--- a/app.py\n+++ b/app.py\n",
            badparts=["os.system(user_input)"],
            goodparts=["subprocess.run(['echo', user_input], shell=False)"],
            provider="local_http",
        )

        record = _build_record(
            sample_id="CWE-78_command_injection_000001",
            spec=spec,
            candidate=candidate,
            model="deepseek-r1:1.5b",
            prompt_sha256="0" * 64,
            seed=1337,
            validation={"passed": True},
            attempt=1,
        )

        self.assertEqual("local_http", record["provider"])
        self.assertEqual("deepseek-r1:1.5b", record["model"])
        self.assertEqual("0" * 64, record["prompt_sha256"])
        self.assertEqual(1337, record["seed"])
        self.assertIn("generated_at", record)
        self.assertEqual({"passed": True, "reason_count": 0, "bandit_findings": 0, "semgrep_findings": 0}, record["validation_summary"])

    def test_record_summary_counts_current_validator_tool_shape(self) -> None:
        spec = SimpleNamespace(
            cwe="CWE-78",
            cwe_name="Command Injection",
            mode="command_injection",
            to_dict=lambda: {"cwe": "CWE-78", "mode": "command_injection"},
        )
        candidate = SimpleNamespace(
            commit_message="Fix command injection",
            filename="app.py",
            vulnerable_code="import os\nos.system(user_input)\n",
            fixed_code="import subprocess\nsubprocess.run(['echo', user_input], shell=False)\n",
            diff="--- a/app.py\n+++ b/app.py\n",
            badparts=["os.system(user_input)"],
            goodparts=["subprocess.run(['echo', user_input], shell=False)"],
            provider="local_http",
        )

        record = _build_record(
            sample_id="CWE-78_command_injection_000001",
            spec=spec,
            candidate=candidate,
            model="deepseek-v4-flash",
            prompt_sha256="0" * 64,
            seed=1337,
            validation={
                "passed": True,
                "reasons": [],
                "bandit_before": {"findings": [{"test_id": "B602"}]},
                "bandit_after": {"findings": []},
                "semgrep_before": {"findings": [{"check_id": "synvul.cwe-78.command-injection"}]},
                "semgrep_after": {"findings": []},
            },
            attempt=1,
        )

        self.assertEqual(1, record["validation_summary"]["bandit_findings"])
        self.assertEqual(1, record["validation_summary"]["semgrep_findings"])

    def test_missing_semgrep_module_is_marked_unavailable(self) -> None:
        result = _run_command(
            [
                "python",
                "-c",
                "import sys; sys.stderr.write(\"No module named 'semgrep'\"); sys.exit(1)",
            ]
        )

        self.assertTrue(result["missing"])


if __name__ == "__main__":
    unittest.main()
