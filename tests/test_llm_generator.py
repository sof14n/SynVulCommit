from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch

from synvulcommit.cwe_registry import CWE_DEFINITIONS
from synvulcommit.llm_generator import (
    GenerationError,
    LocalHTTPProvider,
    OpenAICompatibleProvider,
    _post_json,
    normalize_candidate,
    validate_provider_configuration,
)
from synvulcommit.prompt_builder import build_prompt
from synvulcommit.spec_sampler import GenerationSpec


class OpenAICompatibleProviderTests(unittest.TestCase):
    def test_preflight_reports_all_missing_openai_compatible_variables(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(GenerationError, "SYNVUL_API_KEY, SYNVUL_MODEL"):
                validate_provider_configuration("openai_compatible")

    def test_provider_read_timeout_is_a_recoverable_generation_error(self) -> None:
        with patch("synvulcommit.llm_generator.urllib.request.urlopen", side_effect=TimeoutError("timed out")):
            with self.assertRaisesRegex(GenerationError, "timed out while reading"):
                _post_json("https://api.example.test/chat/completions", {"model": "test"}, {})

    def test_non_object_json_response_is_a_recoverable_generation_error(self) -> None:
        with self.assertRaisesRegex(GenerationError, "JSON that is not an object"):
            normalize_candidate([], "openai_compatible")

    def test_review_override_preflight_uses_reviewer_prefixed_configuration(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(GenerationError, "SYNVUL_REVIEW_API_KEY, SYNVUL_REVIEW_MODEL"):
                validate_provider_configuration("openai_compatible", reviewer_profile=True)

    def test_openai_review_request_uses_review_configuration(self) -> None:
        response = {"choices": [{"message": {"content": json.dumps(_review_payload())}}]}
        environment = {
            "SYNVUL_REVIEW_BASE_URL": "https://review.example.test/v1",
            "SYNVUL_REVIEW_API_KEY": "review-key",
            "SYNVUL_REVIEW_MODEL": "review-model",
            "SYNVUL_REVIEW_TEMPERATURE": "0.1",
        }
        with patch.dict(os.environ, environment, clear=True), patch(
            "synvulcommit.llm_generator._post_json", return_value=response
        ) as post_json:
            result = OpenAICompatibleProvider(reviewer_profile=True).complete_json("review system", "review prompt", max_tokens=512)

        url, payload, headers = post_json.call_args.args
        self.assertEqual("https://review.example.test/v1/chat/completions", url)
        self.assertEqual("Bearer review-key", headers["Authorization"])
        self.assertEqual("review-model", payload["model"])
        self.assertEqual(0.1, payload["temperature"])
        self.assertEqual(512, payload["max_tokens"])
        self.assertEqual("review system", payload["messages"][0]["content"])
        self.assertEqual("pass", result["verdict"])

    def test_local_review_request_supports_ollama_style_configuration(self) -> None:
        response = {"response": json.dumps(_review_payload())}
        environment = {
            "SYNVUL_REVIEW_LOCAL_URL": "http://127.0.0.1:11434/api/generate",
            "SYNVUL_REVIEW_LOCAL_MODEL": "qwen-review",
            "SYNVUL_REVIEW_TEMPERATURE": "0.1",
            "SYNVUL_REVIEW_LOCAL_AUTH": "local-token",
        }
        with patch.dict(os.environ, environment, clear=True), patch(
            "synvulcommit.llm_generator._post_json", return_value=response
        ) as post_json:
            result = LocalHTTPProvider(reviewer_profile=True).complete_json("review system", "review prompt", max_tokens=512)

        url, payload, headers = post_json.call_args.args
        self.assertEqual(environment["SYNVUL_REVIEW_LOCAL_URL"], url)
        self.assertEqual("qwen-review", payload["model"])
        self.assertEqual(512, payload["options"]["num_predict"])
        self.assertEqual(0.1, payload["options"]["temperature"])
        self.assertEqual("local-token", headers["Authorization"])
        self.assertEqual("review system", payload["messages"][0]["content"])
        self.assertEqual("pass", result["verdict"])

    def test_deepseek_uses_low_temperature_and_json_mode(self) -> None:
        response = {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "commit_message": "Fix sample",
                                "filename": "app.py",
                                "vulnerable_code": "print('before')",
                                "fixed_code": "print('after')",
                            }
                        )
                    }
                }
            ]
        }
        spec = GenerationSpec("sql", "CWE-89", "SQL Injection", "sql", "Flask", "direct", "easy", "single_function", 0)
        environment = {
            "SYNVUL_BASE_URL": "https://api.deepseek.com",
            "SYNVUL_API_KEY": "test-key",
            "SYNVUL_MODEL": "deepseek-chat",
        }
        with patch.dict(os.environ, environment, clear=True), patch("synvulcommit.llm_generator._post_json", return_value=response) as post_json:
            result = OpenAICompatibleProvider().generate(spec, "return JSON")

        self.assertEqual(result["filename"], "app.py")
        _, payload, _ = post_json.call_args.args
        self.assertEqual(payload["temperature"], 0.2)
        self.assertEqual(payload["max_tokens"], 1800)
        self.assertEqual(payload["response_format"], {"type": "json_object"})

    def test_openai_compatible_provider_can_disable_thinking_mode(self) -> None:
        response = {"choices": [{"message": {"content": json.dumps(_review_payload())}}]}
        environment = {
            "SYNVUL_REVIEW_BASE_URL": "https://api.deepseek.com",
            "SYNVUL_REVIEW_API_KEY": "review-key",
            "SYNVUL_REVIEW_MODEL": "deepseek-v4-pro",
            "SYNVUL_REVIEW_THINKING_MODE": "disabled",
        }
        with patch.dict(os.environ, environment, clear=True), patch(
            "synvulcommit.llm_generator._post_json", return_value=response
        ) as post_json:
            OpenAICompatibleProvider(reviewer_profile=True).complete_json("review system", "review prompt", max_tokens=1024)

        _, payload, _ = post_json.call_args.args
        self.assertEqual({"type": "disabled"}, payload["thinking"])

    def test_sql_prompt_includes_operational_context_constraints(self) -> None:
        spec = GenerationSpec("sql", "CWE-89", "SQL Injection", "sql", "API", "complex", "hard", "class_based", 0)

        prompt = build_prompt(spec)

        self.assertIn("Use a real HTTP endpoint in Flask or FastAPI", prompt)
        self.assertIn("Use three distinct stages", prompt)
        self.assertIn("build_query helper that returns dynamic SQL", prompt)
        self.assertIn("execute_query helper", prompt)
        self.assertIn("Define at least one class", prompt)
        self.assertIn("keep the query text static", prompt)

    def test_non_sql_complex_prompts_use_requested_cwe_sinks_not_sql_stages(self) -> None:
        for definition in CWE_DEFINITIONS.values():
            if definition.key == "sql":
                continue
            spec = GenerationSpec(
                definition.key,
                definition.cwe,
                definition.name,
                definition.mode,
                "Flask",
                "complex",
                "hard",
                "multi_function",
                0,
            )

            with self.subTest(cwe=definition.cwe):
                prompt = build_prompt(spec)

                self.assertIn("Use three distinct stages", prompt)
                self.assertIn("requested CWE-specific sink", prompt)
                self.assertIn("Do not add SQL query construction, database execution", prompt)
                self.assertNotIn("build_query helper that returns dynamic SQL", prompt)
                self.assertNotIn("execute_query helper that receives that query", prompt)
                self.assertIn("Generate exactly one vulnerability category", prompt)

    def test_xss_prompt_uses_the_deterministic_implementation_variant(self) -> None:
        spec = GenerationSpec("xss", "CWE-79", "Cross-Site Scripting", "xss", "Flask", "direct", "easy", "single_function", 208)

        prompt = build_prompt(spec)

        self.assertIn("local HTML variable with percent-formatting", prompt)
        self.assertIn("Do not use a greeting or hello endpoint", prompt)


if __name__ == "__main__":
    unittest.main()


def _review_payload() -> dict[str, object]:
    return {
        "verdict": "pass",
        "cwe_correct": True,
        "fix_correct": True,
        "context_correct": True,
        "runtime_plausible": True,
        "reason_category": "none",
    }
