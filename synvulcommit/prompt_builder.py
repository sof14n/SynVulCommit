from __future__ import annotations

from .cwe_registry import get_cwe
from .spec_sampler import GenerationSpec


def build_prompt(spec: GenerationSpec) -> str:
    definition = get_cwe(spec.cwe_key)
    vulnerable_requirements = "\n".join(f"- {item}" for item in definition.vulnerable_requirements)
    fixed_requirements = "\n".join(f"- {item}" for item in definition.fixed_requirements)
    prompt_hints = "\n".join(f"- {item}" for item in definition.prompt_hints)

    return f"""You are generating a defensive research dataset item for Python vulnerability detection.

Generate exactly one small, realistic Python security-fix commit.

Task specification:
- CWE: {spec.cwe} ({spec.cwe_name})
- Application type: {spec.application_type}
- Data-flow pattern: {spec.flow_pattern}
- Difficulty: {spec.difficulty}
- Program structure: {spec.structure}

The vulnerable version must satisfy:
{vulnerable_requirements}

The fixed version must satisfy:
{fixed_requirements}

CWE-specific generation hints:
{prompt_hints}

Return only valid JSON. Do not include Markdown, explanations, comments outside JSON, or code fences.

Required JSON object:
{{
  "commit_message": "short Git-style security fix message",
  "filename": "relative/path/to/file.py",
  "vulnerable_code": "complete vulnerable Python file",
  "fixed_code": "complete fixed Python file",
  "vulnerable_lines": ["one or more exact vulnerable lines from vulnerable_code"],
  "fixed_lines": ["one or more exact replacement lines from fixed_code"]
}}

Constraints:
- Keep both versions under 120 lines.
- The vulnerable and fixed files must be syntactically valid Python.
- Keep the example self-contained and toy-sized.
- vulnerable_lines and fixed_lines must contain exact source-code lines, not line numbers.
- Do not include exploit instructions, payloads, real secrets, networking attacks, or destructive behavior.
- The fixed version must preserve the same application behavior while removing the CWE.
"""
