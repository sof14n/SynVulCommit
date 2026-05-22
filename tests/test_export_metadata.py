from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from synvulcommit.cwe_registry import all_cwes
from synvulcommit.export_vudenc import export_records


class ExportMetadataTests(unittest.TestCase):
    def test_export_writes_one_metadata_row_per_sample(self) -> None:
        records = [_record(index, definition.cwe, definition.name, definition.mode) for index, definition in enumerate(all_cwes(), start=1)]

        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "vudenc"
            counts = export_records(records, out_dir)
            metadata_rows = _read_jsonl(out_dir / "metadata.jsonl")
            plain_rows = _count_plain_rows(out_dir)
            metadata_text = (out_dir / "metadata.jsonl").read_text(encoding="utf-8")

        self.assertEqual(7, sum(counts.values()))
        self.assertEqual(7, len(metadata_rows))
        self.assertEqual(7, plain_rows)
        self.assertNotIn("secret-token", metadata_text)
        self.assertNotIn("api_key=", metadata_text)
        for row in metadata_rows:
            self.assertIn("plain_file", row)
            self.assertTrue(row["plain_file"].startswith("plain_"))
            self.assertGreaterEqual(row["row_index"], 1)
            self.assertEqual(row["commit_id"], row["id"])
            self.assertEqual("fixture-provider", row["provenance"]["provider"])
            self.assertEqual("fixture-model", row["provenance"]["model"])
            self.assertEqual("f" * 64, row["provenance"]["prompt_sha256"])
            self.assertEqual(1337, row["provenance"]["seed"])
            self.assertEqual(1, row["provenance"]["attempt"])
            self.assertTrue(row["validation_summary"]["passed"])


def _record(index: int, cwe: str, cwe_name: str, mode: str) -> dict[str, object]:
    sample_id = f"{cwe}_{mode}_{index:06d}"
    return {
        "id": sample_id,
        "cwe": cwe,
        "cwe_name": cwe_name,
        "mode": mode,
        "context": {"mode": mode, "base_url": "https://example.test/?api_key=secret-token"},
        "attempt": 1,
        "seed": 1337,
        "generated_at": "2026-05-22T18:00:00Z",
        "prompt_sha256": "f" * 64,
        "commit_message": f"Fix {mode}",
        "filename": "app.py",
        "vulnerable_code": "def handler(user_input):\n    return user_input\n",
        "fixed_code": "def handler(user_input):\n    return str(user_input)\n",
        "diff": "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,2 @@\n def handler(user_input):\n-    return user_input\n+    return str(user_input)\n",
        "badparts": ["return user_input"],
        "goodparts": ["return str(user_input)"],
        "provider": "fixture-provider",
        "model": "fixture-model",
        "validation": {"passed": True, "reasons": [], "tool_results": {"bandit": {"findings": []}, "semgrep": {"findings": []}}},
        "validation_summary": {"passed": True, "reason_count": 0, "bandit_findings": 0, "semgrep_findings": 0},
    }


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _count_plain_rows(out_dir: Path) -> int:
    total = 0
    for path in out_dir.glob("plain_*"):
        data = json.loads(path.read_text(encoding="utf-8"))
        total += sum(len(commits) for commits in data.values())
    return total


if __name__ == "__main__":
    unittest.main()
