from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from .spec_sampler import GenerationSpec


@dataclass
class StructuralCheckResult:
    passed: bool
    reasons: list[str]
    vulnerable_markers: list[str]
    fixed_markers: list[str]


def run_structural_checks(spec: GenerationSpec, vulnerable_code: str, fixed_code: str) -> StructuralCheckResult:
    reasons: list[str] = []
    vulnerable_markers: list[str] = []
    fixed_markers: list[str] = []

    for label, code in (("vulnerable_code", vulnerable_code), ("fixed_code", fixed_code)):
        try:
            ast.parse(code)
        except SyntaxError as exc:
            reasons.append(f"{label} is not valid Python: {exc}")

    if spec.cwe_key == "sql":
        _require(_has_sql_injection(vulnerable_code), "vulnerable code does not look like SQL injection", reasons)
        _require(_has_parameterized_sql(fixed_code), "fixed code does not use parameterized SQL", reasons)
        _forbid(_has_sql_injection(fixed_code), "fixed code still looks like SQL injection", reasons)
        vulnerable_markers.append("dynamic SQL execution")
        fixed_markers.append("parameterized query")
    elif spec.cwe_key == "command_injection":
        _require(_has_command_injection(vulnerable_code), "vulnerable code does not look like command injection", reasons)
        _require(_has_safe_subprocess(fixed_code), "fixed code does not use safe subprocess arguments", reasons)
        _forbid("shell=True" in fixed_code or "os.system(" in fixed_code, "fixed code still uses shell execution", reasons)
        vulnerable_markers.append("shell command execution")
        fixed_markers.append("argument-list subprocess call")
    elif spec.cwe_key == "directory_traversal":
        _require(_has_path_traversal(vulnerable_code), "vulnerable code does not look like path traversal", reasons)
        _require(_has_path_containment(fixed_code), "fixed code does not check path containment", reasons)
        vulnerable_markers.append("unchecked user path")
        fixed_markers.append("resolved base-path check")
    elif spec.cwe_key == "open_redirect":
        _require(_has_open_redirect(vulnerable_code), "vulnerable code does not look like open redirect", reasons)
        _require(_has_redirect_validation(fixed_code), "fixed code does not validate redirect target", reasons)
        vulnerable_markers.append("unchecked redirect")
        fixed_markers.append("redirect validation")
    elif spec.cwe_key == "remote_code_execution":
        _require(_has_rce(vulnerable_code), "vulnerable code does not use dynamic code execution", reasons)
        _forbid(_has_rce(fixed_code), "fixed code still executes dynamic code", reasons)
        _require(_has_rce_safe_replacement(fixed_code), "fixed code does not show a safe replacement", reasons)
        vulnerable_markers.append("eval/exec")
        fixed_markers.append("literal parser or whitelist")
    elif spec.cwe_key == "xss":
        _require(_has_xss(vulnerable_code), "vulnerable code does not look like XSS", reasons)
        _require(_has_xss_fix(fixed_code), "fixed code does not escape or template user input safely", reasons)
        vulnerable_markers.append("unescaped HTML rendering")
        fixed_markers.append("escaping/template binding")
    elif spec.cwe_key == "xsrf":
        _require(_has_csrf_issue(vulnerable_code), "vulnerable code does not look like CSRF", reasons)
        _require(_has_csrf_fix(fixed_code), "fixed code does not enable CSRF protection", reasons)
        _require(_has_valid_csrf_order(fixed_code), "fixed code initializes CSRF before Flask app exists", reasons)
        _forbid('WTF_CSRF_ENABLED"] = False' in fixed_code or "WTF_CSRF_ENABLED'] = False" in fixed_code, "fixed code disables CSRF", reasons)
        vulnerable_markers.append("missing/disabled CSRF")
        fixed_markers.append("CSRF protection enabled")
    else:
        reasons.append(f"no structural check for {spec.cwe_key}")

    return StructuralCheckResult(
        passed=not reasons,
        reasons=reasons,
        vulnerable_markers=vulnerable_markers,
        fixed_markers=fixed_markers,
    )


def _require(condition: bool, reason: str, reasons: list[str]) -> None:
    if not condition:
        reasons.append(reason)


def _forbid(condition: bool, reason: str, reasons: list[str]) -> None:
    if condition:
        reasons.append(reason)


def _has_sql_injection(code: str) -> bool:
    lowered = code.lower()
    has_execute = ".execute(" in lowered or ".executemany(" in lowered
    has_query = any(token in lowered for token in ("select ", "insert ", "update ", "delete "))
    dynamic = (
        bool(re.search(r"execute\s*\(\s*f[\"']", code))
        or bool(re.search(r"=\s*f[\"']", code))
        or " + " in code
        or " % " in code
        or ".format(" in code
    )
    return has_execute and has_query and dynamic


def _has_parameterized_sql(code: str) -> bool:
    return bool(re.search(r"execute\s*\(\s*[\"'][^\"']*(\?|%s|:[A-Za-z_][A-Za-z0-9_]*)", code)) and ", (" in code


def _has_command_injection(code: str) -> bool:
    return "shell=True" in code or "os.system(" in code or "subprocess.getoutput(" in code


def _has_safe_subprocess(code: str) -> bool:
    return "subprocess.run([" in code and "shell=True" not in code


def _has_path_traversal(code: str) -> bool:
    lowered = code.lower()
    user_path = any(token in lowered for token in ("request.args", "request.form", "input(", "sys.argv"))
    opens_file = "open(" in lowered or ".open(" in lowered or "send_file(" in lowered
    lacks_resolve = ".resolve()" not in lowered and "commonpath" not in lowered and "safe_join" not in lowered
    return user_path and opens_file and lacks_resolve


def _has_path_containment(code: str) -> bool:
    lowered = code.lower()
    return any(token in lowered for token in (".resolve()", "commonpath", "safe_join")) and any(
        token in lowered for token in ("parents", "startswith", "relative_to", "abort(", "raise")
    )


def _has_open_redirect(code: str) -> bool:
    lowered = code.lower()
    return "redirect(" in lowered and any(token in lowered for token in ("request.args", "next", "target", "url"))


def _has_redirect_validation(code: str) -> bool:
    lowered = code.lower()
    return "redirect(" in lowered and any(token in lowered for token in ("urlparse", "netloc", "scheme", "startswith", "allowed"))


def _has_rce(code: str) -> bool:
    return bool(re.search(r"\b(eval|exec|compile)\s*\(", code))


def _has_rce_safe_replacement(code: str) -> bool:
    lowered = code.lower()
    return any(token in lowered for token in ("ast.literal_eval", "whitelist", "allowed_operations", "dispatch"))


def _has_xss(code: str) -> bool:
    lowered = code.lower()
    return (
        "render_template_string" in lowered
        and any(token in code for token in (" + ", "%", ".format(", "Markup("))
        and "escape(" not in lowered
    )


def _has_xss_fix(code: str) -> bool:
    lowered = code.lower()
    return "escape(" in lowered or "{{" in code or "render_template(" in lowered


def _has_csrf_issue(code: str) -> bool:
    lowered = code.lower()
    disabled = "csrf_enabled" in lowered and "false" in lowered
    post_route = any(token in lowered for token in ("@app.post", "methods=[\"post\"", "methods=['post'"))
    has_protection = any(token in lowered for token in ("csrfprotect", "csrf_protect", "csrfmiddlewaretoken"))
    return disabled or (post_route and not has_protection)


def _has_csrf_fix(code: str) -> bool:
    lowered = code.lower()
    return any(token in lowered for token in ("csrfprotect", "csrf_protect", "csrfmiddlewaretoken", "wtf_csrf_enabled\"] = true"))


def _has_valid_csrf_order(code: str) -> bool:
    lowered = code.lower()
    csrf_index = lowered.find("csrfprotect(app)")
    if csrf_index < 0:
        return True
    app_index = lowered.find("app = flask")
    return app_index >= 0 and app_index < csrf_index
