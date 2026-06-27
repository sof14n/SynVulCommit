from __future__ import annotations

from .cwe_registry import get_cwe
from .generation_profile import WINDOW_BALANCED_PROFILE, normalize_generation_profile
from .spec_sampler import GenerationSpec


def build_prompt(spec: GenerationSpec) -> str:
    definition = get_cwe(spec.cwe_key)
    vulnerable_requirements = "\n".join(f"- {item}" for item in definition.vulnerable_requirements)
    fixed_requirements = "\n".join(f"- {item}" for item in definition.fixed_requirements)
    prompt_hints = "\n".join(f"- {item}" for item in definition.prompt_hints)
    context_requirements = _context_requirements(spec)
    diversity_requirement = _diversity_requirement(spec)
    profile = normalize_generation_profile(spec.generation_profile)
    profile_requirement = _profile_requirement(profile)

    return f"""You are generating a defensive research dataset item for Python vulnerability detection.

Generate exactly one {_commit_size_descriptor(profile)} Python security-fix commit.

Task specification:
- CWE: {spec.cwe} ({spec.cwe_name})
- Application type: {spec.application_type}
- Data-flow pattern: {spec.flow_pattern}
- Difficulty: {spec.difficulty}
- Program structure: {spec.structure}
- Generation profile: {profile}

The vulnerable version must satisfy:
{vulnerable_requirements}

The fixed version must satisfy:
{fixed_requirements}

CWE-specific generation hints:
{prompt_hints}

Context acceptance requirements:
{context_requirements}

Deterministic diversity requirement:
{diversity_requirement}

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
{profile_requirement}
- The vulnerable and fixed files must be syntactically valid Python.
- Do not add database schema setup, seed data, test code, or an `if __name__ == "__main__"` block just to make the example runnable.
- vulnerable_lines and fixed_lines must contain exact source-code lines, not line numbers.
- Do not add comments that label code as vulnerable, insecure, fixed, or safe.
- Do not include exploit instructions, payloads, real secrets, networking attacks, or destructive behavior.
- The fixed version must preserve the same application behavior while removing the CWE.
- Generate exactly one vulnerability category: do not add unrelated vulnerable sinks, disabled protections, or security-sensitive flows for another SynVulCommit CWE.
- The fixed version must not retain or introduce any other SynVulCommit CWE pattern.
"""


def _commit_size_descriptor(profile: str) -> str:
    if profile == WINDOW_BALANCED_PROFILE:
        return "realistic medium-sized"
    return "small, realistic"


def _profile_requirement(profile: str) -> str:
    if profile == WINDOW_BALANCED_PROFILE:
        return "\n".join(
            (
                "- Build each version as a realistic 420-900 code-token module.",
                "- Include clean, security-neutral code before and after the vulnerable region so 200-token windows can contain both vulnerable and clean examples.",
                "- Keep the vulnerable/fixed change localized to the requested CWE; the changed vulnerable lines should be a small minority of the file.",
                "- Use realistic helper functions, classes, parsing, routing, validation, or formatting logic; do not add filler comments, dead padding, repeated no-op assignments, or unused toy functions.",
                "- The fixed version must preserve almost all surrounding clean context and should not shrink the module substantially.",
            )
        )
    return "\n".join(
        (
            "- Keep each version under 55 lines and 2,800 characters.",
            "- Keep the example self-contained and toy-sized.",
        )
    )


def _context_requirements(spec: GenerationSpec) -> str:
    application = {
        "Flask": "Use a Flask application with a real request-handling route; do not use another framework.",
        "Django": "Use a Django request handler or Django View and Django database access; do not use another framework.",
        "API": "Use a real HTTP endpoint in Flask or FastAPI; a bare class or CLI program is not an API.",
        "script": "Use a standalone script with input() or sys.argv; do not import or define a web framework application.",
        "CLI": "Use a standalone command-line program with input() or sys.argv; do not import or define a web framework application.",
    }[spec.application_type]
    flow = _flow_requirement(spec)
    structure = {
        "single_function": "Define exactly one function or method and no helper functions or classes.",
        "multi_function": "Define at least two functions or methods and make the requested data flow cross a function boundary.",
        "class_based": "Define at least one class and put the requested data flow through one of its methods.",
    }[spec.structure]
    sql_fix = "For SQL fixes, keep the query text static: use placeholders and bound values, never an f-string, concatenation, percent formatting, or dynamic identifiers in the fixed query."
    django_sql = "For Django raw SQL, use %s placeholders with a parameter list or tuple, never ? placeholders. Serialize fetched rows into JSON-compatible values; do not pass fetchone() or fetchall() output directly to HttpResponse or JsonResponse."
    return "\n".join(
        f"- {item}"
        for item in (application, flow, structure, sql_fix if spec.cwe_key == "sql" else "", django_sql if spec.cwe_key == "sql" and spec.application_type == "Django" else "")
        if item
    )


def _flow_requirement(spec: GenerationSpec) -> str:
    if spec.flow_pattern == "direct":
        return "Read the untrusted value and execute the vulnerable sink in the same function or method."
    if spec.flow_pattern == "indirect":
        return "Read the untrusted value in one handler function or method, then pass it to a distinct helper that reaches the sink."
    if spec.cwe_key == "sql":
        return (
            "Use three distinct stages: a source handler/input function, a build_query helper that returns dynamic SQL, "
            "and an execute_query helper that receives that query and calls execute(). The source or its immediate "
            "coordinator must call both helpers."
        )
    return (
        "Use three distinct stages: a source handler/input function, an intermediate helper that forwards or transforms "
        "the untrusted value, and a final helper or handler that reaches the requested CWE-specific sink. Do not add SQL "
        "query construction, database execution, or another CWE's sink."
    )


def _diversity_requirement(spec: GenerationSpec) -> str:
    if spec.cwe_key != "xss" or spec.application_type not in {"Flask", "API"}:
        return "Use an implementation shape that is materially different from a generic greeting or hello endpoint."
    variants = (
        "Build a local HTML variable with percent-formatting from a request value, then pass it to render_template_string. "
        "Do not use a greeting or hello endpoint. The fixed code must escape the value before formatting.",
        "Use a direct f-string HTML response from a request value. Do not use a greeting or hello endpoint. The fixed code "
        "must escape the value before interpolation.",
        "Build a local HTML variable with str.format from a request value, then pass it to render_template_string. Do not use "
        "a greeting or hello endpoint. The fixed code must escape the value before formatting.",
        "Use Flask Response with a local HTML variable assembled from a request value. Do not use a greeting or hello endpoint. "
        "The fixed code must escape the value before rendering.",
    )
    return variants[spec.sample_index % len(variants)]
