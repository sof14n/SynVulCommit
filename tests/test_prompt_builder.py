from __future__ import annotations

import unittest

from synvulcommit.generation_profile import WINDOW_BALANCED_PROFILE
from synvulcommit.prompt_builder import build_prompt
from synvulcommit.spec_sampler import GenerationSpec


class PromptBuilderTests(unittest.TestCase):
    def test_compact_profile_keeps_small_file_constraints(self) -> None:
        prompt = build_prompt(_spec())

        self.assertIn("Generation profile: compact", prompt)
        self.assertIn("Keep each version under 55 lines and 2,800 characters.", prompt)
        self.assertIn("Keep the example self-contained and toy-sized.", prompt)
        self.assertNotIn("420-900 code-token module", prompt)

    def test_window_balanced_profile_requests_clean_context_and_localized_changes(self) -> None:
        prompt = build_prompt(_spec(WINDOW_BALANCED_PROFILE))

        self.assertIn("Generation profile: window_balanced", prompt)
        self.assertIn("420-900 code-token module", prompt)
        self.assertIn("clean, security-neutral code before and after the vulnerable region", prompt)
        self.assertIn("changed vulnerable lines should be a small minority", prompt)
        self.assertIn("do not add filler comments", prompt)
        self.assertNotIn("Keep each version under 55 lines", prompt)


def _spec(profile: str = "compact") -> GenerationSpec:
    return GenerationSpec(
        "sql",
        "CWE-89",
        "SQL Injection",
        "sql",
        "Flask",
        "indirect",
        "medium",
        "multi_function",
        0,
        profile,
    )


if __name__ == "__main__":
    unittest.main()
