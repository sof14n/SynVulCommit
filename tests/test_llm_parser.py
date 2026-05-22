from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from synvulcommit.export_vudenc import export_records
from synvulcommit.llm_generator import GenerationError, _extract_text, normalize_candidate, parse_candidate_text
from synvulcommit.storage import append_jsonl


def _raw_candidate() -> dict[str, object]:
    vulnerable_line = 'query = f"SELECT id FROM users WHERE name = \'{name}\'"'
    fixed_line = 'return db.execute("SELECT id FROM users WHERE name = ?", (name,)).fetchall()'
    return {
        "commit_message": "Fix SQL injection in user lookup",
        "filename": "users.py",
        "vulnerable_code": f"""
import sqlite3


def lookup_user(name):
    db = sqlite3.connect("users.db")
    {vulnerable_line}
    return db.execute(query).fetchall()
""",
        "fixed_code": f"""
import sqlite3


def lookup_user(name):
    db = sqlite3.connect("users.db")
    {fixed_line}
""",
        "vulnerable_lines": [vulnerable_line],
        "fixed_lines": [fixed_line],
    }


def _candidate_json() -> str:
    return json.dumps(_raw_candidate(), sort_keys=True)


def _normalized_fields(text: str) -> dict[str, object]:
    raw = parse_candidate_text(text)
    candidate = normalize_candidate(raw, "fixture")
    return {
        "commit_message": candidate.commit_message,
        "filename": candidate.filename,
        "vulnerable_code": candidate.vulnerable_code,
        "fixed_code": candidate.fixed_code,
        "badparts": candidate.badparts,
        "goodparts": candidate.goodparts,
    }


class CandidateParserTests(unittest.TestCase):
    def test_plain_thinking_and_prose_outputs_parse_to_same_candidate(self) -> None:
        expected = _normalized_fields(_candidate_json())
        fixtures = [
            _candidate_json(),
            f"<think>private reasoning {{\"draft\": true}}</think>\n{_candidate_json()}",
            f"Draft object: {{\"draft\": true}}\nFinal JSON:\n{_candidate_json()}",
            f"<think>unfinished reasoning {{\"draft\": true\nFinal JSON:\n{_candidate_json()}",
        ]

        for fixture in fixtures:
            with self.subTest(fixture=fixture[:40]):
                self.assertEqual(expected, _normalized_fields(fixture))

    def test_invalid_output_is_rejected_without_reasoning_preview(self) -> None:
        secret_reasoning = "private chain-of-thought that must not be persisted"

        with self.assertRaises(GenerationError) as captured:
            parse_candidate_text(f"<think>{secret_reasoning}</think>\nNo JSON here.")

        self.assertEqual("no_valid_json", captured.exception.reason)
        self.assertNotIn(secret_reasoning, str(captured.exception))
        self.assertNotIn("<think>", str(captured.exception))

    def test_ollama_thinking_field_is_not_candidate_text(self) -> None:
        secret_reasoning = "private Ollama thinking field"
        text = _extract_text({"response": _candidate_json(), "thinking": secret_reasoning})

        self.assertEqual(_candidate_json(), text)
        self.assertNotIn(secret_reasoning, text)

    def test_stripped_reasoning_is_not_written_to_dataset_artifacts(self) -> None:
        secret_reasoning = "private chain-of-thought that must not reach disk"
        raw = parse_candidate_text(f"<think>{secret_reasoning}</think>\n{_candidate_json()}")
        candidate = normalize_candidate(raw, "local_http")
        record = {
            "id": "CWE-89_sql_000001",
            "cwe": "CWE-89",
            "cwe_name": "SQL Injection",
            "mode": "sql",
            "context": {"mode": "sql"},
            "attempt": 1,
            "validation": {"passed": True},
            **candidate.to_record_fields(),
        }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            append_jsonl(root / "samples.jsonl", record)
            append_jsonl(
                root / "rejected.jsonl",
                {
                    "provider": "local_http",
                    "model": "fixture-model",
                    "cwe": "CWE-89",
                    "attempt": 1,
                    "reject_reason": ["no_valid_json"],
                    "error": "provider returned no valid JSON object",
                },
            )
            export_records([record], root / "vudenc")

            persisted = "\n".join(path.read_text(encoding="utf-8") for path in root.rglob("*") if path.is_file())

        self.assertNotIn(secret_reasoning, persisted)
        self.assertNotIn("<think>", persisted)


if __name__ == "__main__":
    unittest.main()
