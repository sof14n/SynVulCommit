from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from synvulcommit import validator
from synvulcommit.llm_generator import GeneratedCommit
from synvulcommit.spec_sampler import GenerationSpec
from synvulcommit.structural_checks import StructuralCheckResult


class AnalyzerExecutionTests(unittest.TestCase):
    def test_cross_cwe_semgrep_finding_after_fix_rejects_candidate(self) -> None:
        before = validator.ToolRun("semgrep", True, "success", [], 1, [{"check_id": "synvul.cwe-89.sql-injection"}], None)
        after = validator.ToolRun("semgrep", True, "success", [], 1, [{"check_id": "synvul.cwe-352.csrf-disabled"}], None)
        clean_bandit = validator.ToolRun("bandit", True, "success", [], 0, [], None)
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            validator, "run_structural_checks", return_value=StructuralCheckResult(True, [], [], [])
        ), patch.object(validator, "_run_bandit_pair", return_value=(clean_bandit, clean_bandit)), patch.object(
            validator, "_run_semgrep_pair", return_value=(before, after)
        ):
            result = validator.validate_candidate(_sql_spec(), _candidate(), Path(tmp), Path(tmp), require_tools=True)

        self.assertFalse(result.passed)
        self.assertIn("Semgrep reports other SynVulCommit rule ids after fix: synvul.cwe-352.csrf-disabled", result.reasons)

    def test_expected_semgrep_finding_before_fix_remains_required(self) -> None:
        before = validator.ToolRun("semgrep", True, "success", [], 0, [], None)
        after = validator.ToolRun("semgrep", True, "success", [], 0, [], None)
        clean_bandit = validator.ToolRun("bandit", True, "success", [], 0, [], None)
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            validator, "run_structural_checks", return_value=StructuralCheckResult(True, [], [], [])
        ), patch.object(validator, "_run_bandit_pair", return_value=(clean_bandit, clean_bandit)), patch.object(
            validator, "_run_semgrep_pair", return_value=(before, after)
        ):
            result = validator.validate_candidate(_sql_spec(), _candidate(), Path(tmp), Path(tmp), require_tools=True)

        self.assertFalse(result.passed)
        self.assertIn("Semgrep did not report expected ids before fix: synvul.cwe-89.sql-injection", result.reasons)

    def test_target_cwe_semgrep_finding_after_fix_remains_rejected(self) -> None:
        before = validator.ToolRun("semgrep", True, "success", [], 1, [{"check_id": "synvul.cwe-89.sql-injection"}], None)
        after = validator.ToolRun("semgrep", True, "success", [], 1, [{"check_id": "synvul.cwe-89.sql-injection"}], None)
        clean_bandit = validator.ToolRun("bandit", True, "success", [], 0, [], None)
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            validator, "run_structural_checks", return_value=StructuralCheckResult(True, [], [], [])
        ), patch.object(validator, "_run_bandit_pair", return_value=(clean_bandit, clean_bandit)), patch.object(
            validator, "_run_semgrep_pair", return_value=(before, after)
        ):
            result = validator.validate_candidate(_sql_spec(), _candidate(), Path(tmp), Path(tmp), require_tools=True)

        self.assertFalse(result.passed)
        self.assertIn("Semgrep still reports expected ids after fix: synvul.cwe-89.sql-injection", result.reasons)

    def test_semgrep_exit_one_with_json_findings_is_a_successful_scan(self) -> None:
        completed = {
            "status": "completed",
            "returncode": 1,
            "stdout": json.dumps({"results": [{"check_id": "synvul.cwe-89.sql-injection"}]}),
            "error": None,
        }
        with tempfile.TemporaryDirectory() as tmp, patch.object(validator, "_run_command", return_value=completed):
            result = validator._run_semgrep(Path(tmp) / "candidate.py", Path(tmp))

        self.assertTrue(result.available)
        self.assertEqual(result.status, "success")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.findings[0]["check_id"], "synvul.cwe-89.sql-injection")

    def test_sql_rule_matches_dynamic_sql_but_not_html_interpolation(self) -> None:
        rules_dir = Path(__file__).resolve().parents[1] / "synvulcommit" / "rules"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sql_file = root / "sql.py"
            sql_file.write_text(
                "def build_query(name):\n"
                "    return f\"SELECT * FROM users WHERE name = '{name}'\"\n",
                encoding="utf-8",
            )
            html_file = root / "xss.py"
            html_file.write_text(
                "def greeting(name):\n"
                "    return f\"<h1>Hello, {name}!</h1>\"\n",
                encoding="utf-8",
            )

            sql_result = validator._run_semgrep(sql_file, rules_dir)
            html_result = validator._run_semgrep(html_file, rules_dir)

        sql_ids = validator._semgrep_ids(sql_result)
        html_ids = validator._semgrep_ids(html_result)
        self.assertTrue(sql_result.available, sql_result.error)
        self.assertTrue(html_result.available, html_result.error)
        self.assertIn("synvul.cwe-89.sql-injection", sql_ids)
        self.assertNotIn("synvul.cwe-89.sql-injection", html_ids)

    def test_xss_rule_matches_indirect_dynamic_html_but_not_escaped_html(self) -> None:
        rules_dir = Path(__file__).resolve().parents[1] / "synvulcommit" / "rules"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vulnerable = root / "vulnerable.py"
            vulnerable.write_text(
                "from flask import render_template_string\n\n"
                "def build_html(name):\n"
                "    return \"<h1>\" + name + \"</h1>\"\n\n"
                "def render_page(html):\n"
                "    return render_template_string(html)\n",
                encoding="utf-8",
            )
            fixed = root / "fixed.py"
            fixed.write_text(
                "from flask import escape, render_template_string\n\n"
                "def build_html(name):\n"
                "    return \"<h1>\" + escape(name) + \"</h1>\"\n\n"
                "def render_page(html):\n"
                "    return render_template_string(html)\n",
                encoding="utf-8",
            )

            vulnerable_result = validator._run_semgrep(vulnerable, rules_dir)
            fixed_result = validator._run_semgrep(fixed, rules_dir)

        vulnerable_ids = validator._semgrep_ids(vulnerable_result)
        fixed_ids = validator._semgrep_ids(fixed_result)
        self.assertTrue(vulnerable_result.available, vulnerable_result.error)
        self.assertTrue(fixed_result.available, fixed_result.error)
        self.assertIn("synvul.cwe-79.xss-helper", vulnerable_ids)
        self.assertNotIn("synvul.cwe-79.xss-helper", fixed_ids)

    def test_xss_taint_rule_matches_django_response_but_honors_escape(self) -> None:
        rules_dir = Path(__file__).resolve().parents[1] / "synvulcommit" / "rules"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vulnerable = root / "vulnerable.py"
            vulnerable.write_text(
                "from django.http import HttpResponse\n\n"
                "def hello(request):\n"
                "    name = request.GET.get('name', 'World')\n"
                "    return HttpResponse('<h1>Hello, ' + name + '</h1>')\n",
                encoding="utf-8",
            )
            fixed = root / "fixed.py"
            fixed.write_text(
                "from django.http import HttpResponse\n"
                "from django.utils.html import escape\n\n"
                "def hello(request):\n"
                "    name = request.GET.get('name', 'World')\n"
                "    safe_name = escape(name)\n"
                "    return HttpResponse('<h1>Hello, ' + safe_name + '</h1>')\n",
                encoding="utf-8",
            )

            vulnerable_result = validator._run_semgrep(vulnerable, rules_dir)
            fixed_result = validator._run_semgrep(fixed, rules_dir)

        vulnerable_ids = validator._semgrep_ids(vulnerable_result)
        fixed_ids = validator._semgrep_ids(fixed_result)
        self.assertTrue(vulnerable_result.available, vulnerable_result.error)
        self.assertTrue(fixed_result.available, fixed_result.error)
        self.assertIn("synvul.cwe-79.xss", vulnerable_ids)
        self.assertNotIn("synvul.cwe-79.xss", fixed_ids)

    def test_xss_taint_rule_matches_flask_response_with_mimetype(self) -> None:
        rules_dir = Path(__file__).resolve().parents[1] / "synvulcommit" / "rules"
        with tempfile.TemporaryDirectory() as tmp:
            vulnerable = Path(tmp) / "vulnerable.py"
            vulnerable.write_text(
                "from flask import Response, request\n\n"
                "def search():\n"
                "    query = request.args.get('q', '')\n"
                "    html = '<h1>' + query + '</h1>'\n"
                "    return Response(html, mimetype='text/html')\n",
                encoding="utf-8",
            )
            result = validator._run_semgrep(vulnerable, rules_dir)

        self.assertTrue(result.available, result.error)
        self.assertIn("synvul.cwe-79.xss", validator._semgrep_ids(result))

    def test_csrf_rule_does_not_flag_a_post_route_without_explicit_csrf_disablement(self) -> None:
        rules_dir = Path(__file__).resolve().parents[1] / "synvulcommit" / "rules"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            post_route = root / "post_route.py"
            post_route.write_text(
                "from flask import Flask\n\n"
                "app = Flask(__name__)\n\n"
                "@app.post('/calculate')\n"
                "def calculate():\n"
                "    return 'ok'\n",
                encoding="utf-8",
            )
            disabled = root / "disabled.py"
            disabled.write_text(
                "from flask import Flask\n\n"
                "app = Flask(__name__)\n"
                "app.config['WTF_CSRF_ENABLED'] = False\n",
                encoding="utf-8",
            )
            post_result = validator._run_semgrep(post_route, rules_dir)
            disabled_result = validator._run_semgrep(disabled, rules_dir)

        self.assertNotIn("synvul.cwe-352.csrf-disabled", validator._semgrep_ids(post_result))
        self.assertIn("synvul.cwe-352.csrf-disabled", validator._semgrep_ids(disabled_result))

    def test_sql_rule_matches_dynamic_append_to_static_select_query(self) -> None:
        rules_dir = Path(__file__).resolve().parents[1] / "synvulcommit" / "rules"
        with tempfile.TemporaryDirectory() as tmp:
            vulnerable = Path(tmp) / "vulnerable.py"
            vulnerable.write_text(
                "def search(cursor, category):\n"
                "    query = 'SELECT id FROM products WHERE 1 = 1'\n"
                "    query += f\" AND category = '{category}'\"\n"
                "    return cursor.execute(query)\n",
                encoding="utf-8",
            )
            result = validator._run_semgrep(vulnerable, rules_dir)

        self.assertTrue(result.available, result.error)
        self.assertIn("synvul.cwe-89.sql-injection", validator._semgrep_ids(result))

    def test_xss_taint_rule_ignores_non_html_and_template_render_responses(self) -> None:
        rules_dir = Path(__file__).resolve().parents[1] / "synvulcommit" / "rules"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            command_result = root / "command_result.py"
            command_result.write_text(
                "from django.http import HttpResponse\n\n"
                "def ping(request):\n"
                "    host = request.GET.get('host', '')\n"
                "    result = type('Result', (), {'stdout': host})()\n"
                "    return HttpResponse(result.stdout)\n",
                encoding="utf-8",
            )
            template_response = root / "template_response.py"
            template_response.write_text(
                "from django.http import HttpResponse\n"
                "from django.template import Context, Template\n\n"
                "def hello(request):\n"
                "    name = request.GET.get('name', 'World')\n"
                "    template = Template('<h1>{{ name }}</h1>')\n"
                "    return HttpResponse(template.render(Context({'name': name})))\n",
                encoding="utf-8",
            )

            command_result_scan = validator._run_semgrep(command_result, rules_dir)
            template_response_scan = validator._run_semgrep(template_response, rules_dir)

        self.assertTrue(command_result_scan.available, command_result_scan.error)
        self.assertTrue(template_response_scan.available, template_response_scan.error)
        self.assertNotIn("synvul.cwe-79.xss", validator._semgrep_ids(command_result_scan))
        self.assertNotIn("synvul.cwe-79.xss", validator._semgrep_ids(template_response_scan))

    def test_semgrep_crash_is_not_treated_as_a_clean_scan(self) -> None:
        completed = {
            "status": "completed",
            "returncode": 1,
            "stdout": "",
            "error": "ImportError: cannot import name 'LogData'",
        }
        with tempfile.TemporaryDirectory() as tmp, patch.object(validator, "_run_command", return_value=completed):
            result = validator._run_semgrep(Path(tmp) / "candidate.py", Path(tmp))

        self.assertFalse(result.available)
        self.assertEqual(result.status, "error")
        self.assertIn("no JSON output", result.error or "")

    def test_batched_tool_scans_split_findings_by_before_and_after_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            before = root / "vulnerable.py"
            after = root / "fixed.py"
            bandit_completed = {
                "status": "completed",
                "returncode": 1,
                "stdout": json.dumps(
                    {
                        "results": [
                            {"test_id": "B608", "filename": str(before)},
                            {"test_id": "B307", "filename": str(after)},
                        ]
                    }
                ),
                "error": None,
            }
            semgrep_completed = {
                "status": "completed",
                "returncode": 1,
                "stdout": json.dumps(
                    {
                        "results": [
                            {"check_id": "before-rule", "path": str(before)},
                            {"check_id": "after-rule", "path": str(after)},
                        ]
                    }
                ),
                "error": None,
            }
            with patch.object(validator, "_run_command", return_value=bandit_completed) as run_bandit:
                bandit_before, bandit_after = validator._run_bandit_pair(before, after)
            with patch.object(validator, "_run_command", return_value=semgrep_completed) as run_semgrep:
                semgrep_before, semgrep_after = validator._run_semgrep_pair(before, after, root)

        self.assertEqual(["B608"], [item["test_id"] for item in bandit_before.findings])
        self.assertEqual(["B307"], [item["test_id"] for item in bandit_after.findings])
        self.assertEqual(["before-rule"], [item["check_id"] for item in semgrep_before.findings])
        self.assertEqual(["after-rule"], [item["check_id"] for item in semgrep_after.findings])
        self.assertIn(str(before), run_bandit.call_args.args[0])
        self.assertIn(str(after), run_bandit.call_args.args[0])
        self.assertIn(str(before), run_semgrep.call_args.args[0])
        self.assertIn(str(after), run_semgrep.call_args.args[0])

    def test_non_strict_tool_error_is_a_warning_not_a_false_semgrep_rejection(self) -> None:
        failed = validator.ToolRun("semgrep", False, "error", [], 1, [], "ImportError: broken dependency")
        reasons: list[str] = []
        warnings: list[str] = []

        validator._handle_tool_availability("Semgrep", failed, failed, False, reasons, warnings)

        self.assertEqual(reasons, [])
        self.assertEqual(len(warnings), 1)
        self.assertIn("failed to run correctly", warnings[0])

    def test_strict_tool_error_rejects_the_candidate(self) -> None:
        failed = validator.ToolRun("semgrep", False, "error", [], 1, [], "ImportError: broken dependency")
        reasons: list[str] = []
        warnings: list[str] = []

        validator._handle_tool_availability("Semgrep", failed, failed, True, reasons, warnings)

        self.assertEqual(warnings, [])
        self.assertEqual(len(reasons), 1)
        self.assertIn("failed to run correctly", reasons[0])


if __name__ == "__main__":
    unittest.main()


def _sql_spec() -> GenerationSpec:
    return GenerationSpec("sql", "CWE-89", "SQL Injection", "sql", "Flask", "direct", "easy", "single_function", 0)


def _candidate() -> GeneratedCommit:
    return GeneratedCommit(
        commit_message="Fix SQL injection",
        filename="app.py",
        vulnerable_code="def lookup(value):\n    return value\n",
        fixed_code="def lookup(value):\n    return str(value)\n",
        diff="--- a/app.py\n+++ b/app.py\n",
        badparts=["return value"],
        goodparts=["return str(value)"],
        provider="test",
        raw_response={},
    )
