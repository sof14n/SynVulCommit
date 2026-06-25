from __future__ import annotations

import os
import unittest

from synvulcommit.llm_generator import GeneratedCommit, validate_provider_configuration
from synvulcommit.reviewer import REVIEW_VERDICTS, review_candidate
from synvulcommit.spec_sampler import GenerationSpec


class LiveReviewerIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("SYNVUL_RUN_LIVE_REVIEW_TESTS") == "1",
        "set SYNVUL_RUN_LIVE_REVIEW_TESTS=1 to call the configured OpenAI-compatible reviewer",
    )
    def test_configured_openai_compatible_reviewer_returns_a_strict_review(self) -> None:
        validate_provider_configuration("openai_compatible")

        result = review_candidate("openai_compatible", _spec(), _candidate())

        self.assertIn(result.verdict, REVIEW_VERDICTS)
        self.assertIsInstance(result.cwe_correct, bool)
        self.assertIsInstance(result.fix_correct, bool)
        self.assertIsInstance(result.context_correct, bool)
        self.assertIsInstance(result.runtime_plausible, bool)

    @unittest.skipUnless(
        os.environ.get("SYNVUL_RUN_LIVE_LOCAL_REVIEW_TESTS") == "1",
        "set SYNVUL_RUN_LIVE_LOCAL_REVIEW_TESTS=1 to call the configured local reviewer profile",
    )
    def test_configured_local_reviewer_returns_a_strict_review(self) -> None:
        validate_provider_configuration("local_http", reviewer_profile=True)

        result = review_candidate("local_http", _spec(), _candidate(), reviewer_profile=True)

        self.assertIn(result.verdict, REVIEW_VERDICTS)
        self.assertIsInstance(result.cwe_correct, bool)
        self.assertIsInstance(result.fix_correct, bool)
        self.assertIsInstance(result.context_correct, bool)
        self.assertIsInstance(result.runtime_plausible, bool)


def _spec() -> GenerationSpec:
    return GenerationSpec("sql", "CWE-89", "SQL Injection", "sql", "Flask", "direct", "easy", "single_function", 0)


def _candidate() -> GeneratedCommit:
    return GeneratedCommit(
        commit_message="Fix SQL injection",
        filename="app.py",
        vulnerable_code=(
            "import sqlite3\n\n"
            "def find_user(username):\n"
            "    db = sqlite3.connect('users.db')\n"
            "    return db.execute(f\"SELECT * FROM users WHERE username = '{username}'\").fetchall()\n"
        ),
        fixed_code=(
            "import sqlite3\n\n"
            "def find_user(username):\n"
            "    db = sqlite3.connect('users.db')\n"
            "    return db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchall()\n"
        ),
        diff="--- a/app.py\n+++ b/app.py\n",
        badparts=["return db.execute(f\"SELECT * FROM users WHERE username = '{username}'\").fetchall()"],
        goodparts=["return db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchall()"],
        provider="integration-test",
        raw_response={},
    )


if __name__ == "__main__":
    unittest.main()
