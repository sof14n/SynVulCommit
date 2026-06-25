from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from synvulcommit.llm_generator import GeneratedCommit, GenerationError
from synvulcommit.reviewer import build_review_prompt, parse_review_result, review_candidate, validate_reviewer_configuration
from synvulcommit.spec_sampler import GenerationSpec


class ReviewerSchemaTests(unittest.TestCase):
    def test_valid_passing_review_is_accepted(self) -> None:
        result = parse_review_result(_review_payload(), "mock", None)

        self.assertTrue(result.passed)
        self.assertEqual("none", result.reason_category)
        self.assertEqual("completed", result.to_dict()["status"])

    def test_fail_and_unsure_reviews_are_valid_non_passing_results(self) -> None:
        fail = parse_review_result(
            _review_payload(verdict="fail", fix_correct=False, reason_category="incomplete_fix"),
            "mock",
            None,
        )
        unsure = parse_review_result(
            _review_payload(verdict="unsure", context_correct=False, reason_category="wrong_context"),
            "mock",
            None,
        )

        self.assertFalse(fail.passed)
        self.assertFalse(unsure.passed)

    def test_inconsistent_or_malformed_review_is_rejected(self) -> None:
        invalid_payloads = (
            _review_payload(cwe_correct=False),
            _review_payload(verdict="fail", reason_category="none"),
            {"verdict": "pass"},
            _review_payload(reason_category="C:/temporary/secret"),
            {**_review_payload(), "explanation": "not allowed"},
            "not JSON",
        )

        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(GenerationError):
                    parse_review_result(payload, "mock", None)

    def test_review_prompt_is_blinded_to_provider_metadata(self) -> None:
        prompt = build_review_prompt(_spec(), _candidate())

        self.assertIn("CWE-89", prompt)
        self.assertIn("def lookup(value):", prompt)
        self.assertIn("introduces another SynVulCommit CWE", prompt)
        self.assertIn('reason_category "wrong_cwe"', prompt)
        self.assertNotIn("deepseek", prompt.lower())
        self.assertNotIn("raw_response", prompt)

    def test_same_provider_default_and_override_profile_select_expected_model(self) -> None:
        with patch.dict(
            os.environ,
            {
                "SYNVUL_MODEL": "generator-model",
                "SYNVUL_REVIEW_MODEL": "reviewer-model",
                "SYNVUL_REVIEW_MAX_TOKENS": "512",
            },
            clear=True,
        ):
            same_provider = review_candidate("mock", _spec(), _candidate())
            override = review_candidate("mock", _spec(), _candidate(), reviewer_profile=True)

        self.assertIsNone(same_provider.model)
        self.assertIsNone(override.model)
        self.assertTrue(same_provider.passed)
        self.assertTrue(override.passed)

    def test_invalid_reviewer_token_limit_fails_preflight(self) -> None:
        with patch.dict(os.environ, {"SYNVUL_REVIEW_MAX_TOKENS": "12"}, clear=True):
            with self.assertRaisesRegex(GenerationError, "SYNVUL_REVIEW_MAX_TOKENS"):
                validate_reviewer_configuration()


def _review_payload(**changes: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "verdict": "pass",
        "cwe_correct": True,
        "fix_correct": True,
        "context_correct": True,
        "runtime_plausible": True,
        "reason_category": "none",
    }
    payload.update(changes)
    return payload


def _spec() -> GenerationSpec:
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
        provider="mock",
        raw_response={"provider": "deepseek"},
    )


if __name__ == "__main__":
    unittest.main()
