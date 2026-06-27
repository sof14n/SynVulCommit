from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from synvulcommit.cwe_registry import all_cwes
from synvulcommit.export_vudenc import export_records


class VudencExportTests(unittest.TestCase):
    def test_clean_plain_export_and_sanitized_metadata_sidecar(self) -> None:
        record = _record()
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "vudenc"
            counts = export_records([record], out_dir)
            plain = json.loads((out_dir / "plain_sql").read_text(encoding="utf-8"))
            metadata = _read_jsonl(out_dir / "metadata.jsonl")
            exported_text = "\n".join(
                path.read_text(encoding="utf-8") for path in out_dir.iterdir() if path.is_file()
            )

        self.assertEqual(1, counts["sql"])
        self.assertEqual(["CWE-89_sql_000001"], list(plain["synvulcommit/sql"]))
        commit = plain["synvulcommit/sql"]["CWE-89_sql_000001"]
        self.assertEqual({"msg", "files"}, set(commit))
        self.assertNotIn("synvulcommit", commit)
        exported_file = commit["files"]["api/users.py"]
        self.assertEqual("\ndef lookup(name):\n    return name\n", exported_file["source"])
        self.assertEqual(["return name"], exported_file["changes"][0]["badparts"])

        self.assertEqual(1, len(metadata))
        row = metadata[0]
        self.assertEqual("plain_sql", row["plain_file"])
        self.assertEqual(1, row["row_index"])
        self.assertEqual("api/users.py", row["filename"])
        self.assertEqual("compact", row["generation_profile"])
        self.assertEqual(
            {
                "cwe_key": "sql",
                "cwe": "CWE-89",
                "cwe_name": "SQL Injection",
                "mode": "sql",
                "application_type": "Flask",
                "flow_pattern": "direct",
                "difficulty": "easy",
                "structure": "single_function",
                "sample_index": 0,
            },
            row["context"],
        )
        self.assertEqual({"provider": "openai_compatible", "model": "deepseek-chat", "prompt_sha256": "a" * 64, "seed": 1337, "attempt": 1, "generated_at": "2026-06-22T00:00:00Z"}, row["provenance"])
        self.assertEqual(["B608"], row["validation_summary"]["bandit"]["before"]["finding_ids"])
        self.assertEqual(["synvul.cwe-89.sql-injection"], row["validation_summary"]["semgrep"]["before"]["finding_ids"])
        self.assertEqual(
            {
                "required": True,
                "status": "completed",
                "verdict": "pass",
                "cwe_correct": True,
                "fix_correct": True,
                "context_correct": True,
                "runtime_plausible": True,
                "reason_category": "none",
                "provider": "openai_compatible",
                "model": "reviewer-model",
            },
            row["review_summary"],
        )
        self.assertNotIn("review", commit)

        for forbidden in ("C:\\Users\\Lenovo", "C:/tmp", "secret-token", "Authorization", "https://api.example.test"):
            self.assertNotIn(forbidden, exported_text)

    def test_legacy_record_omits_unavailable_provenance_fields(self) -> None:
        record = _record()
        for field in ("model", "prompt_sha256", "seed", "generated_at"):
            record.pop(field)
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "vudenc"
            export_records([record], out_dir)
            metadata = _read_jsonl(out_dir / "metadata.jsonl")

        self.assertEqual({"provider": "openai_compatible", "attempt": 1}, metadata[0]["provenance"])

    def test_metadata_includes_sanitized_window_balance_summary_without_plain_export_changes(self) -> None:
        record = _record()
        record["generation_profile"] = "window_balanced"
        record["context"]["generation_profile"] = "window_balanced"
        record["validation"]["window_balance"] = {
            "window_size": 200,
            "stride": 5,
            "vulnerable_token_count": 500,
            "fixed_token_count": 490,
            "positive_window_count": 4,
            "negative_window_count": 20,
            "badpart_token_count": 12,
            "badpart_token_ratio": 0.024,
            "fixed_token_retention": 0.98,
            "unsafe": "C:\\Users\\Lenovo\\secret-token",
        }
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "vudenc"
            export_records([record], out_dir)
            plain = json.loads((out_dir / "plain_sql").read_text(encoding="utf-8"))
            metadata = _read_jsonl(out_dir / "metadata.jsonl")

        commit = plain["synvulcommit/sql"]["CWE-89_sql_000001"]
        self.assertEqual({"msg", "files"}, set(commit))
        self.assertNotIn("generation_profile", json.dumps(plain))
        self.assertEqual("window_balanced", metadata[0]["generation_profile"])
        self.assertEqual(
            {
                "window_size": 200,
                "stride": 5,
                "vulnerable_token_count": 500,
                "fixed_token_count": 490,
                "positive_window_count": 4,
                "negative_window_count": 20,
                "badpart_token_count": 12,
                "badpart_token_ratio": 0.024,
                "fixed_token_retention": 0.98,
            },
            metadata[0]["validation_summary"]["window_balance"],
        )
        self.assertNotIn("secret-token", json.dumps(metadata))

    def test_unsafe_commit_message_is_replaced(self) -> None:
        record = _record()
        record["commit_message"] = "Fix C:\\Users\\Lenovo\\secret-token"
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "vudenc"
            export_records([record], out_dir)
            plain = json.loads((out_dir / "plain_sql").read_text(encoding="utf-8"))

        commit = plain["synvulcommit/sql"]["CWE-89_sql_000001"]
        self.assertEqual("Synthetic security fix", commit["msg"])

    def test_empty_export_writes_all_modes_and_an_empty_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "vudenc"
            counts = export_records([], out_dir)
            metadata = (out_dir / "metadata.jsonl").read_text(encoding="utf-8")
            plain_contents = {
                definition.mode: json.loads((out_dir / f"plain_{definition.mode}").read_text(encoding="utf-8"))
                for definition in all_cwes()
            }

        self.assertEqual({definition.mode: 0 for definition in all_cwes()}, counts)
        self.assertEqual("", metadata)
        self.assertTrue(all(content == {} for content in plain_contents.values()))


def _record() -> dict[str, object]:
    return {
        "id": "CWE-89_sql_000001",
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
            "sample_index": 0,
            "base_url": "https://api.example.test/?api_key=secret-token",
        },
        "attempt": 1,
        "seed": 1337,
        "generated_at": "2026-06-22T00:00:00Z",
        "prompt_sha256": "a" * 64,
        "commit_message": "Use bound SQL parameters",
        "filename": "api/users.py",
        "vulnerable_code": "def lookup(name):\n    return name\n",
        "fixed_code": "def lookup(name):\n    return str(name)\n",
        "diff": "--- a/api/users.py\n+++ b/api/users.py\n@@ -1,2 +1,2 @@\n def lookup(name):\n-    return name\n+    return str(name)\n",
        "badparts": ["return name"],
        "goodparts": ["return str(name)"],
        "provider": "openai_compatible",
        "model": "deepseek-chat",
        "review": {
            "required": True,
            "status": "completed",
            "verdict": "pass",
            "cwe_correct": True,
            "fix_correct": True,
            "context_correct": True,
            "runtime_plausible": True,
            "reason_category": "none",
            "provider": "openai_compatible",
            "model": "reviewer-model",
            "raw_response": "Authorization: Bearer secret-token",
            "endpoint": "https://api.example.test",
        },
        "validation": {
            "passed": True,
            "reasons": [],
            "warnings": [],
            "structural": {"passed": True, "vulnerable_markers": ["dynamic SQL execution"], "fixed_markers": ["parameterized query"]},
            "bandit_before": {
                "available": True,
                "status": "success",
                "command": ["C:\\Users\\Lenovo\\VulnerabilityDetection\\Code\\lab 5\\.venv\\Scripts\\python.exe", "-m", "bandit"],
                "findings": [{"test_id": "B608", "filename": "C:\\tmp\\vulnerable.py"}],
                "error": "Authorization: Bearer secret-token",
            },
            "bandit_after": {"available": True, "status": "success", "findings": []},
            "semgrep_before": {
                "available": True,
                "status": "success",
                "command": ["semgrep", "https://api.example.test"],
                "findings": [{"check_id": "synvul.cwe-89.sql-injection", "path": "C:/tmp/vulnerable.py"}],
            },
            "semgrep_after": {"available": True, "status": "success", "findings": []},
        },
    }


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


if __name__ == "__main__":
    unittest.main()
