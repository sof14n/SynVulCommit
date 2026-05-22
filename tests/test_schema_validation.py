from __future__ import annotations
import unittest

from synvulcommit.cwe_registry import get_cwe
from synvulcommit.llm_generator import GenerationError, normalize_candidate, parse_candidate_text, validate_raw_candidate
from synvulcommit.spec_sampler import GenerationSpec


class SchemaValidationTests(unittest.TestCase):
    def test_valid_mock_shaped_output_passes_schema(self) -> None:
        candidate = normalize_candidate(_valid_raw(), "fixture", spec=_spec())

        self.assertEqual("Fix SQL injection", candidate.commit_message)
        self.assertEqual(["query = f\"SELECT * FROM users WHERE name = '{name}'\""], candidate.badparts)
        self.assertEqual(['cursor.execute("SELECT * FROM users WHERE name = ?", (name,))'], candidate.goodparts)

    def test_missing_required_field_is_rejected(self) -> None:
        raw = _valid_raw()
        del raw["fixed_code"]

        self.assertSchemaError(raw, "fixed_code")

    def test_empty_required_string_is_rejected(self) -> None:
        raw = _valid_raw()
        raw["commit_message"] = " "

        self.assertSchemaError(raw, "commit_message")

    def test_wrong_required_type_is_rejected(self) -> None:
        raw = _valid_raw()
        raw["vulnerable_code"] = ["not", "a", "string"]

        self.assertSchemaError(raw, "vulnerable_code")

    def test_malformed_json_is_rejected_before_schema(self) -> None:
        with self.assertRaises(GenerationError) as captured:
            parse_candidate_text('{"commit_message": }')

        self.assertEqual("json_parse_error", captured.exception.reason)

    def test_wrong_cwe_metadata_is_rejected(self) -> None:
        raw = _valid_raw()
        raw["cwe"] = "CWE-79"

        self.assertSchemaError(raw, "cwe")

    def test_empty_bad_or_good_parts_are_rejected(self) -> None:
        raw = _valid_raw()
        raw["vulnerable_lines"] = []
        self.assertSchemaError(raw, "vulnerable_lines")

        raw = _valid_raw()
        raw["fixed_lines"] = [" "]
        self.assertSchemaError(raw, "fixed_lines[0]")

    def test_non_list_bad_or_good_parts_are_rejected(self) -> None:
        raw = _valid_raw()
        raw["vulnerable_lines"] = "query line"

        self.assertSchemaError(raw, "vulnerable_lines")

    def assertSchemaError(self, raw: dict[str, object], field_path: str) -> None:
        with self.assertRaises(GenerationError) as captured:
            validate_raw_candidate(raw, spec=_spec())

        self.assertEqual("schema_validation", captured.exception.reason)
        self.assertEqual(field_path, captured.exception.field_path)
        self.assertIn(field_path, str(captured.exception))


def _spec() -> GenerationSpec:
    definition = get_cwe("sql")
    return GenerationSpec(
        cwe_key=definition.key,
        cwe=definition.cwe,
        cwe_name=definition.name,
        mode=definition.mode,
        application_type="Flask",
        flow_pattern="direct",
        difficulty="easy",
        structure="single_function",
        sample_index=0,
    )


def _valid_raw() -> dict[str, object]:
    vulnerable_line = "query = f\"SELECT * FROM users WHERE name = '{name}'\""
    fixed_line = 'cursor.execute("SELECT * FROM users WHERE name = ?", (name,))'
    return {
        "cwe": "CWE-89",
        "mode": "sql",
        "cwe_key": "sql",
        "commit_message": "Fix SQL injection",
        "filename": "app.py",
        "vulnerable_code": "\n".join(
            [
                "import sqlite3",
                "",
                "def find_user(name):",
                "    cursor = sqlite3.connect('users.db').cursor()",
                f"    {vulnerable_line}",
                "    cursor.execute(query)",
                "    return cursor.fetchall()",
            ]
        ),
        "fixed_code": "\n".join(
            [
                "import sqlite3",
                "",
                "def find_user(name):",
                "    cursor = sqlite3.connect('users.db').cursor()",
                f"    {fixed_line}",
                "    return cursor.fetchall()",
            ]
        ),
        "vulnerable_lines": [vulnerable_line],
        "fixed_lines": [fixed_line],
    }


if __name__ == "__main__":
    unittest.main()
