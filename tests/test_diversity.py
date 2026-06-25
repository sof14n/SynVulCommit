from __future__ import annotations

import unittest

from synvulcommit.diversity import DiversityIndex


class DiversityIndexTests(unittest.TestCase):
    def test_exact_code_pair_duplicate_is_rejected(self) -> None:
        index = DiversityIndex()
        first = _record("sample-1", _simple_code("name", "total", "1"), _simple_fixed("name", "total", "1"))
        duplicate = dict(first, id="sample-2")

        self._assert_accepted(index, first)
        accepted, reason = index.accepts(duplicate)

        self.assertFalse(accepted)
        self.assertEqual("duplicate code pair hash", reason)
        self.assertEqual("exact_code_pair", index.last_rejection["check"])
        self.assertEqual("sample-1", index.last_rejection["matched_id"])

    def test_renamed_variables_and_literals_are_rejected_by_normalized_ast(self) -> None:
        index = DiversityIndex()
        first = _record("sample-1", _simple_code("name", "total", "1"), _simple_fixed("name", "total", "1"))
        renamed = _record("sample-2", _simple_code("username", "score", "99"), _simple_fixed("username", "score", "100"))

        self._assert_accepted(index, first)
        accepted, reason = index.accepts(renamed)

        self.assertFalse(accepted)
        self.assertEqual("duplicate normalized AST fingerprint", reason)
        self.assertEqual("normalized_ast", index.last_rejection["check"])

    def test_normalized_ast_duplicate_is_rejected_across_cwes(self) -> None:
        index = DiversityIndex()
        first = _record("sample-1", _simple_code("name", "total", "1"), _simple_fixed("name", "total", "1"))
        different_cwe = _record("sample-2", _simple_code("user", "value", "2"), _simple_fixed("user", "value", "3"))
        different_cwe["cwe"] = "CWE-78"
        different_cwe["mode"] = "command_injection"

        self._assert_accepted(index, first)
        accepted, reason = index.accepts(different_cwe)

        self.assertFalse(accepted)
        self.assertEqual("duplicate normalized AST fingerprint", reason)
        self.assertEqual("sample-1", index.last_rejection["matched_id"])

    def test_token_near_duplicate_is_rejected_with_similarity_detail(self) -> None:
        index = DiversityIndex()
        first = _record("sample-1", _long_code(""), _long_fixed(""))
        near_duplicate = _record("sample-2", _long_code("    marker = step_17\n"), _long_fixed("    marker = step_17\n"))

        self._assert_accepted(index, first)
        accepted, reason = index.accepts(near_duplicate)

        self.assertFalse(accepted)
        self.assertTrue(reason.startswith("near-duplicate token shingles similarity"))
        self.assertEqual("near_duplicate", index.last_rejection["check"])
        self.assertGreaterEqual(index.last_rejection["similarity"], 0.90)
        self.assertEqual(0.90, index.last_rejection["threshold"])

    def test_distinct_same_cwe_sample_is_accepted(self) -> None:
        index = DiversityIndex()
        first = _record("sample-1", _simple_code("name", "total", "1"), _simple_fixed("name", "total", "1"))
        distinct = _record(
            "sample-2",
            "import subprocess\n\ndef ping(host):\n    return subprocess.run('ping ' + host, shell=True)\n",
            "import subprocess\n\ndef ping(host):\n    return subprocess.run(['ping', host], shell=False)\n",
        )

        self._assert_accepted(index, first)
        self._assert_accepted(index, distinct)

    def test_existing_records_participate_in_duplicate_checks(self) -> None:
        first = _record("sample-1", _simple_code("name", "total", "1"), _simple_fixed("name", "total", "1"))
        duplicate = dict(first, id="sample-2")
        index = DiversityIndex()
        index.load_existing([first])

        accepted, reason = index.accepts(duplicate)

        self.assertFalse(accepted)
        self.assertEqual("duplicate code pair hash", reason)

    def _assert_accepted(self, index: DiversityIndex, record: dict[str, object]) -> None:
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
    return _long_code(extra_line).replace("return result", "return str(result)")
