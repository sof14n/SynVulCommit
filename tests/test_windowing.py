from __future__ import annotations

import unittest

from synvulcommit.windowing import analyze_window_balance, code_token_count


class WindowingTests(unittest.TestCase):
    def test_short_file_has_only_positive_window_when_badpart_is_present(self) -> None:
        code = "def lookup(value):\n    return value\n"
        summary = analyze_window_balance(code, ["return value"], "def lookup(value):\n    return str(value)\n")

        self.assertLess(summary["vulnerable_token_count"], 200)
        self.assertEqual(1, summary["positive_window_count"])
        self.assertEqual(0, summary["negative_window_count"])

    def test_long_localized_badpart_has_positive_and_negative_windows(self) -> None:
        code = _long_code()
        fixed = code.replace("    query = f\"SELECT id FROM users WHERE name = '{name}'\"", "    query = \"SELECT id FROM users WHERE name = ?\"")
        fixed = fixed.replace("    return cursor.execute(query)", "    return cursor.execute(query, (name,))")
        summary = analyze_window_balance(
            code,
            ["query = f\"SELECT id FROM users WHERE name = '{name}'", "return cursor.execute(query)"],
            fixed,
        )

        self.assertGreaterEqual(summary["vulnerable_token_count"], 420)
        self.assertLessEqual(summary["vulnerable_token_count"], 900)
        self.assertGreaterEqual(summary["positive_window_count"], 1)
        self.assertGreaterEqual(summary["negative_window_count"], 1)
        self.assertLess(summary["badpart_token_ratio"], 0.15)

    def test_code_token_count_uses_python_like_tokens(self) -> None:
        self.assertEqual(5, code_token_count("value = user_input + 1\n"))


def _long_code() -> str:
    lines = ["def clean_before(value):", "    result = value"]
    for index in range(43):
        lines.append(f"    result = result + {index}")
    lines.extend(
        [
            "    return result",
            "",
            "def lookup(cursor, name):",
            "    query = f\"SELECT id FROM users WHERE name = '{name}'\"",
            "    return cursor.execute(query)",
            "",
            "def clean_after(items):",
            "    total = 0",
        ]
    )
    for index in range(43):
        lines.append(f"    total = total + len(str(items[{index % 3}]))")
    lines.append("    return total")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    unittest.main()
