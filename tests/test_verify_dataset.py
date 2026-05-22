from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from synvulcommit.cwe_registry import all_cwes
from synvulcommit.export_vudenc import export_records
from synvulcommit.storage import append_jsonl
from synvulcommit.verify_dataset import verify_dataset, main as verify_main


class VerifyDatasetTests(unittest.TestCase):
    def test_valid_seven_sample_fixture_passes_with_expected_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            samples_path, rejected_path, vudenc_dir = _write_valid_fixture(root)

            metrics = verify_dataset(samples_path, rejected_path=rejected_path, vudenc_dir=vudenc_dir)

        self.assertEqual("passed", metrics["status"])
        self.assertEqual(7, metrics["accepted_total"])
        self.assertEqual(2, metrics["rejected_total"])
        self.assertAlmostEqual(7 / 9, metrics["acceptance_rate"])
        self.assertEqual(1.0, metrics["average_attempts_per_accepted"])
        self.assertEqual(7, metrics["vudenc_integrity"]["metadata_rows"])
        self.assertEqual([], metrics["errors"])
        self.assertEqual({"bandit": 0, "semgrep": 0}, metrics["validation_tool_findings"])
        self.assertEqual({"reason": "schema_validation", "count": 2}, metrics["top_rejection_reasons"][0])

    def test_json_cli_output_has_stable_keys_and_exits_zero_for_valid_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            samples_path, rejected_path, vudenc_dir = _write_valid_fixture(root)
            output = io.StringIO()
            argv = [
                "verify_dataset",
                "--input",
                str(samples_path),
                "--rejected",
                str(rejected_path),
                "--vudenc",
                str(vudenc_dir),
                "--json",
            ]

            with patch("sys.argv", argv), contextlib.redirect_stdout(output):
                exit_code = verify_main()

            data = json.loads(output.getvalue())

        self.assertEqual(0, exit_code)
        for key in (
            "status",
            "accepted_total",
            "accepted_by_cwe",
            "rejected_total",
            "acceptance_rate",
            "average_attempts_per_accepted",
            "top_rejection_reasons",
            "validation_tool_findings",
            "duplicate_sample_ids",
            "duplicate_code_fingerprints",
            "missing_required_fields",
            "vudenc_integrity",
            "error_count",
            "errors",
        ):
            self.assertIn(key, data)

    def test_missing_required_field_exits_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            records = _records()
            del records[0]["fixed_code"]
            samples_path = root / "samples.jsonl"
            for record in records:
                append_jsonl(samples_path, record)

            exit_code = _run_verifier("--input", str(samples_path), "--json")
            metrics = verify_dataset(samples_path)

        self.assertEqual(1, exit_code)
        self.assertEqual("failed", metrics["status"])
        self.assertEqual("fixed_code", metrics["missing_required_fields"][0]["field"])

    def test_duplicate_sample_id_exits_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            records = _records()
            records[1]["id"] = records[0]["id"]
            samples_path = root / "samples.jsonl"
            for record in records:
                append_jsonl(samples_path, record)

            exit_code = _run_verifier("--input", str(samples_path), "--json")
            metrics = verify_dataset(samples_path)

        self.assertEqual(1, exit_code)
        self.assertEqual([records[0]["id"]], metrics["duplicate_sample_ids"])

    def test_duplicate_code_fingerprint_exits_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            records = _records()
            records[1]["vulnerable_code"] = records[0]["vulnerable_code"]
            records[1]["fixed_code"] = records[0]["fixed_code"]
            samples_path = root / "samples.jsonl"
            for record in records:
                append_jsonl(samples_path, record)

            exit_code = _run_verifier("--input", str(samples_path), "--json")
            metrics = verify_dataset(samples_path)

        self.assertEqual(1, exit_code)
        self.assertEqual(1, len(metrics["duplicate_code_fingerprints"]))
        self.assertEqual(sorted([records[0]["id"], records[1]["id"]]), metrics["duplicate_code_fingerprints"][0]["ids"])

    def test_vudenc_export_row_mismatch_exits_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            samples_path, _, vudenc_dir = _write_valid_fixture(root)
            metadata_path = vudenc_dir / "metadata.jsonl"
            rows = [json.loads(line) for line in metadata_path.read_text(encoding="utf-8").splitlines()]
            rows[0]["commit_id"] = "wrong-id"
            metadata_path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n", encoding="utf-8")

            exit_code = _run_verifier("--input", str(samples_path), "--vudenc", str(vudenc_dir), "--json")
            metrics = verify_dataset(samples_path, vudenc_dir=vudenc_dir)

        self.assertEqual(1, exit_code)
        self.assertEqual("failed", metrics["status"])
        self.assertTrue(metrics["vudenc_integrity"]["metadata_row_mismatches"])


def _run_verifier(*args: str) -> int:
    with patch("sys.argv", ["verify_dataset", *args]), contextlib.redirect_stdout(io.StringIO()):
        return verify_main()


def _write_valid_fixture(root: Path) -> tuple[Path, Path, Path]:
    samples_path = root / "samples.jsonl"
    rejected_path = root / "rejected.jsonl"
    records = _records()
    for record in records:
        append_jsonl(samples_path, record)
    append_jsonl(rejected_path, {"reject_reason": ["schema_validation"], "attempt": 1})
    append_jsonl(rejected_path, {"reject_reason": ["schema_validation"], "attempt": 2})
    vudenc_dir = root / "vudenc"
    export_records(records, vudenc_dir)
    return samples_path, rejected_path, vudenc_dir


def _records() -> list[dict[str, object]]:
    return [_record(index, definition.cwe, definition.name, definition.mode) for index, definition in enumerate(all_cwes(), start=1)]


def _record(index: int, cwe: str, cwe_name: str, mode: str) -> dict[str, object]:
    sample_id = f"{cwe}_{mode}_{index:06d}"
    return {
        "id": sample_id,
        "cwe": cwe,
        "cwe_name": cwe_name,
        "mode": mode,
        "context": {
            "mode": mode,
            "application_type": "Flask",
            "flow_pattern": "direct",
            "difficulty": "easy",
            "structure": "single_function",
        },
        "attempt": 1,
        "seed": 1337,
        "generated_at": "2026-05-22T18:00:00Z",
        "prompt_sha256": f"{index:064d}"[-64:],
        "commit_message": f"Fix {mode}",
        "filename": "app.py",
        "vulnerable_code": f"def handler_{index}(user_input):\n    return user_input\n",
        "fixed_code": f"def handler_{index}(user_input):\n    return str(user_input)\n",
        "diff": f"--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,2 @@\n def handler_{index}(user_input):\n-    return user_input\n+    return str(user_input)\n",
        "badparts": ["return user_input"],
        "goodparts": ["return str(user_input)"],
        "provider": "fixture-provider",
        "model": "fixture-model",
        "validation": {"passed": True, "reasons": [], "tool_results": {"bandit": {"findings": []}, "semgrep": {"findings": []}}},
        "validation_summary": {"passed": True, "reason_count": 0, "bandit_findings": 0, "semgrep_findings": 0},
    }


if __name__ == "__main__":
    unittest.main()
