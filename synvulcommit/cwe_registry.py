from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CWEDefinition:
    key: str
    cwe: str
    name: str
    mode: str
    description: str
    vulnerable_requirements: tuple[str, ...]
    fixed_requirements: tuple[str, ...]
    prompt_hints: tuple[str, ...]
    semgrep_rule_ids: tuple[str, ...]
    bandit_ids: tuple[str, ...]


CWE_DEFINITIONS: dict[str, CWEDefinition] = {
    "sql": CWEDefinition(
        key="sql",
        cwe="CWE-89",
        name="SQL Injection",
        mode="sql",
        description="Untrusted input reaches a SQL query through string construction.",
        vulnerable_requirements=(
            "Build a SQL query by concatenating, formatting, or interpolating user input.",
            "Execute the constructed SQL string.",
        ),
        fixed_requirements=(
            "Use parameterized queries or bound parameters.",
            "Do not concatenate user input into the query text.",
        ),
        prompt_hints=(
            "Good vulnerable sink example: cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
            "Good fixed sink example: cursor.execute(\"SELECT * FROM users WHERE name = ?\", (name,))",
        ),
        semgrep_rule_ids=("synvul.cwe-89.sql-injection",),
        bandit_ids=("B608",),
    ),
    "command_injection": CWEDefinition(
        key="command_injection",
        cwe="CWE-78",
        name="Command Injection",
        mode="command_injection",
        description="Untrusted input is included in an OS command.",
        vulnerable_requirements=(
            "Pass user input into a shell command.",
            "Use shell=True, os.system, or equivalent dangerous execution.",
        ),
        fixed_requirements=(
            "Use an argument list instead of shell=True.",
            "Validate or constrain the user-controlled value.",
        ),
        prompt_hints=(
            "Good vulnerable sink example: subprocess.run(\"ping \" + host, shell=True)",
            "Good fixed sink example: subprocess.run([\"ping\", host], shell=False)",
        ),
        semgrep_rule_ids=("synvul.cwe-78.command-injection",),
        bandit_ids=("B602", "B605"),
    ),
    "directory_traversal": CWEDefinition(
        key="directory_traversal",
        cwe="CWE-22",
        name="Path Traversal",
        mode="directory_traversal",
        description="Untrusted path data can escape the intended base directory.",
        vulnerable_requirements=(
            "Read a file path controlled by user input.",
            "Join or open the path without normalizing and checking the base directory.",
        ),
        fixed_requirements=(
            "Resolve the requested path against a fixed base directory.",
            "Reject paths outside the base directory with a path-aware containment check, never a string-prefix comparison.",
        ),
        prompt_hints=(
            "Good vulnerable sink example: open(os.path.join(BASE_DIR, name))",
            "Good fixed pattern: requested = (BASE_DIR / name).resolve(); use requested.is_relative_to(BASE_DIR) or requested.relative_to(BASE_DIR), never str(requested).startswith(str(BASE_DIR)).",
        ),
        semgrep_rule_ids=("synvul.cwe-22.path-traversal",),
        bandit_ids=(),
    ),
    "open_redirect": CWEDefinition(
        key="open_redirect",
        cwe="CWE-601",
        name="Open Redirect",
        mode="open_redirect",
        description="Untrusted URL data controls a redirect target.",
        vulnerable_requirements=(
            "Read a next/target/url parameter from the request.",
            "Redirect to that value without checking whether it is local or allowed.",
        ),
        fixed_requirements=(
            "Allow only relative local redirects or an explicit allowlist.",
            "Fallback to a safe route for invalid targets.",
        ),
        prompt_hints=(
            "Good vulnerable sink example: return redirect(request.args.get(\"next\", \"/\"))",
            "Good fixed pattern: parse with urlparse and reject targets with scheme or netloc.",
        ),
        semgrep_rule_ids=("synvul.cwe-601.open-redirect",),
        bandit_ids=(),
    ),
    "remote_code_execution": CWEDefinition(
        key="remote_code_execution",
        cwe="CWE-94",
        name="Remote Code Execution",
        mode="remote_code_execution",
        description="Untrusted input is evaluated as Python code.",
        vulnerable_requirements=(
            "Read code-like data from request input, CLI input, or a file.",
            "Execute it with eval, exec, compile, or an equivalent dynamic evaluator.",
        ),
        fixed_requirements=(
            "Replace dynamic execution with a safe parser, whitelist, or fixed dispatch table.",
            "Do not evaluate arbitrary user-controlled code.",
        ),
        prompt_hints=(
            "Good vulnerable sink example: result = eval(expression)",
            "Good fixed pattern: use ast.literal_eval for literals or a whitelist dispatch table for operations.",
        ),
        semgrep_rule_ids=("synvul.cwe-94.remote-code-execution",),
        bandit_ids=("B307", "B102"),
    ),
    "xss": CWEDefinition(
        key="xss",
        cwe="CWE-79",
        name="Cross-Site Scripting",
        mode="xss",
        description="Untrusted input is inserted into HTML without escaping.",
        vulnerable_requirements=(
            "Read a user-controlled string.",
            "Return or render HTML that includes the string without escaping.",
        ),
        fixed_requirements=(
            "Escape user-controlled HTML or use a template engine with autoescaping.",
            "Do not mark untrusted input as safe.",
        ),
        prompt_hints=(
            "Good vulnerable sink example: return render_template_string(\"<h1>\" + name + \"</h1>\")",
            "Good fixed pattern: use escape(name) or render_template_string(\"<h1>{{ name }}</h1>\", name=name).",
        ),
        semgrep_rule_ids=("synvul.cwe-79.xss", "synvul.cwe-79.xss-helper"),
        bandit_ids=("B703",),
    ),
    "xsrf": CWEDefinition(
        key="xsrf",
        cwe="CWE-352",
        name="Cross-Site Request Forgery",
        mode="xsrf",
        description="A state-changing request lacks CSRF protection.",
        vulnerable_requirements=(
            "Create a POST route or state-changing handler.",
            "Omit CSRF protection or explicitly disable it.",
        ),
        fixed_requirements=(
            "Enable framework CSRF protection or require a verified CSRF token.",
            "Keep state-changing actions behind token validation.",
        ),
        prompt_hints=(
            "Good vulnerable marker example: app.config[\"WTF_CSRF_ENABLED\"] = False on a POST route.",
            "Good fixed marker example: from flask_wtf.csrf import CSRFProtect; csrf = CSRFProtect(app).",
        ),
        semgrep_rule_ids=("synvul.cwe-352.csrf-disabled",),
        bandit_ids=(),
    ),
}


def all_cwes() -> list[CWEDefinition]:
    return list(CWE_DEFINITIONS.values())


def all_semgrep_rule_ids() -> frozenset[str]:
    return frozenset(rule_id for definition in all_cwes() for rule_id in definition.semgrep_rule_ids)


def get_cwe(key_or_mode: str) -> CWEDefinition:
    normalized = key_or_mode.lower().strip()
    for definition in CWE_DEFINITIONS.values():
        if normalized in {definition.key, definition.mode, definition.cwe.lower()}:
            return definition
    raise KeyError(f"unknown CWE key or mode: {key_or_mode}")
