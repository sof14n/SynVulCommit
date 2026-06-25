from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from .spec_sampler import GenerationSpec


_KNOWN_FRAMEWORK_IMPORTS: dict[str, frozenset[str]] = {
    "flask": frozenset(
        {
            "Blueprint",
            "Flask",
            "Response",
            "abort",
            "current_app",
            "escape",
            "flash",
            "g",
            "jsonify",
            "make_response",
            "redirect",
            "render_template",
            "render_template_string",
            "request",
            "send_file",
            "send_from_directory",
            "session",
            "stream_with_context",
            "url_for",
        }
    ),
    "flask_wtf": frozenset({"CSRFProtect", "FlaskForm"}),
    "wtforms": frozenset({"BooleanField", "PasswordField", "SelectField", "StringField", "SubmitField"}),
    "django.db": frozenset({"connection"}),
    "django.http": frozenset(
        {
            "FileResponse",
            "HttpRequest",
            "HttpResponse",
            "HttpResponseBadRequest",
            "HttpResponseForbidden",
            "HttpResponseNotAllowed",
            "HttpResponseNotFound",
            "HttpResponsePermanentRedirect",
            "HttpResponseRedirect",
            "HttpResponseServerError",
            "JsonResponse",
            "StreamingHttpResponse",
        }
    ),
    "django.utils.html": frozenset({"escape", "format_html"}),
    "django.views": frozenset({"View"}),
    "markupsafe": frozenset({"Markup", "escape"}),
}


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
            tree = ast.parse(code)
        except SyntaxError as exc:
            reasons.append(f"{label} is not valid Python: {exc}")
        else:
            _check_known_framework_imports(tree, label, reasons)

    _check_context(spec, vulnerable_code, reasons)

    if spec.cwe_key == "sql":
        _require(_has_sql_injection(vulnerable_code), "vulnerable code does not look like SQL injection", reasons)
        _require(
            _has_parameterized_sql(fixed_code, spec.application_type),
            "fixed code does not use parameterized SQL",
            reasons,
        )
        _forbid(_has_sql_injection(fixed_code), "fixed code still looks like SQL injection", reasons)
        if spec.application_type == "Django":
            _forbid(
                _has_unserialized_django_query_response(fixed_code),
                "fixed Django handler returns database rows without serialization",
                reasons,
            )
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
        _require(_has_path_containment(fixed_code), "fixed code does not use a path-safe containment check", reasons)
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


def _check_known_framework_imports(tree: ast.AST, label: str, reasons: list[str]) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or node.level != 0 or not node.module:
            continue
        allowed_names = _KNOWN_FRAMEWORK_IMPORTS.get(node.module)
        if allowed_names is None:
            continue
        for imported in node.names:
            if imported.name != "*" and imported.name not in allowed_names:
                reasons.append(f"{label} imports unknown symbol '{imported.name}' from '{node.module}'")


def _has_sql_injection(code: str) -> bool:
    lowered = code.lower()
    has_execute = ".execute(" in lowered or ".executemany(" in lowered
    has_query = any(token in lowered for token in ("select ", "insert ", "update ", "delete "))
    dynamic = (
        bool(re.search(r"execute\s*\(\s*f[\"']", code))
        or bool(re.search(r"=\s*f[\"']", code))
        or bool(re.search(r"return\s+f[\"']", code))
        or " + " in code
        or " % " in code
        or ".format(" in code
    )
    return has_execute and has_query and dynamic


def _has_parameterized_sql(code: str, application_type: str | None = None) -> bool:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return False

    static_queries = _static_query_assignments(tree)
    helper_queries = _static_query_helper_returns(tree)
    helper_assignments, bound_value_names = _static_query_helper_assignments(tree, helper_queries)
    static_queries.update(helper_assignments)
    execution_helpers = _parameterized_execution_helpers(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) or node.func.attr not in {"execute", "executemany"}:
            if not isinstance(node, ast.Call) or _called_function_name(node) not in execution_helpers or len(node.args) < 2:
                continue
            if not _is_bound_values_or_known_name(node.args[1], bound_value_names):
                continue
            query = _static_query_text(node.args[0], static_queries, helper_queries)
            if query and _has_sql_placeholder(query, application_type):
                return True
            continue
        if len(node.args) < 2 or not _is_bound_values_or_known_name(node.args[1], bound_value_names):
            continue
        query = _static_query_text(node.args[0], static_queries, helper_queries)
        if query and _has_sql_placeholder(query, application_type):
            return True
    return False


def _static_query_assignments(tree: ast.AST) -> dict[str, str]:
    queries: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if value is None:
            continue
        query = _static_query_text(value, queries)
        if not query:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                queries[target.id] = query
    return queries


def _static_query_helper_returns(tree: ast.AST) -> dict[str, tuple[str, bool]]:
    helpers: dict[str, tuple[str, bool]] = {}
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        assignments = _static_query_assignments(function)
        for node in ast.walk(function):
            if not isinstance(node, ast.Return) or node.value is None:
                continue
            value = node.value
            if isinstance(value, ast.Tuple) and value.elts:
                query = _static_query_text(value.elts[0], assignments)
                has_bound_values = len(value.elts) > 1 and _is_bound_values(value.elts[1])
            else:
                query = _static_query_text(value, assignments)
                has_bound_values = False
            if query:
                helpers[function.name] = (query, has_bound_values)
    return helpers


def _static_query_helper_assignments(
    tree: ast.AST, helpers: dict[str, tuple[str, bool]]
) -> tuple[dict[str, str], set[str]]:
    queries: dict[str, str] = {}
    bound_value_names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        helper = _called_function_name(node.value)
        if helper not in helpers:
            continue
        query, returns_bound_values = helpers[helper]
        for target in node.targets:
            if isinstance(target, ast.Name):
                queries[target.id] = query
            elif isinstance(target, ast.Tuple) and target.elts:
                first = target.elts[0]
                if isinstance(first, ast.Name):
                    queries[first.id] = query
                if returns_bound_values and len(target.elts) > 1 and isinstance(target.elts[1], ast.Name):
                    bound_value_names.add(target.elts[1].id)
    return queries, bound_value_names


def _parameterized_execution_helpers(tree: ast.AST) -> set[str]:
    helpers: set[str] = set()
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        parameter_names = {argument.arg for argument in function.args.args}
        for node in ast.walk(function):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) or node.func.attr not in {"execute", "executemany"}:
                continue
            if len(node.args) < 2:
                continue
            if all(isinstance(argument, ast.Name) and argument.id in parameter_names for argument in node.args[:2]):
                helpers.add(function.name)
    return helpers


def _called_function_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def _static_query_text(
    node: ast.AST, queries: dict[str, str], helpers: dict[str, tuple[str, bool]] | None = None
) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return queries.get(node.id)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "text" and node.args:
        return _static_query_text(node.args[0], queries, helpers)
    if isinstance(node, ast.Call) and helpers:
        helper = _called_function_name(node)
        if helper in helpers:
            return helpers[helper][0]
    return None


def _is_bound_values(node: ast.AST) -> bool:
    return isinstance(node, (ast.Tuple, ast.List, ast.Dict))


def _is_bound_values_or_known_name(node: ast.AST, known_names: set[str]) -> bool:
    return _is_bound_values(node) or isinstance(node, ast.Name) and node.id in known_names


def _has_sql_placeholder(query: str, application_type: str | None = None) -> bool:
    if application_type == "Django":
        return "%s" in query
    return "?" in query or "%s" in query or bool(re.search(r":[A-Za-z_][A-Za-z0-9_]*", query))


def _has_unserialized_django_query_response(code: str) -> bool:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return False

    fetched_names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        if not _is_fetch_call(node.value):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        fetched_names.update(target.id for target in targets if isinstance(target, ast.Name))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_django_response_call(node):
            continue
        values = [*node.args, *(keyword.value for keyword in node.keywords)]
        if any(_contains_direct_fetched_name(value, fetched_names) for value in values):
            return True
    return False


def _is_fetch_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"fetchone", "fetchall"}


def _is_django_response_call(node: ast.Call) -> bool:
    return isinstance(node.func, ast.Name) and node.func.id in {"HttpResponse", "JsonResponse"}


def _contains_direct_fetched_name(node: ast.AST, fetched_names: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in fetched_names
    if isinstance(node, ast.Dict):
        return any(isinstance(value, ast.Name) and value.id in fetched_names for value in node.values)
    return False


def _check_context(spec: GenerationSpec, vulnerable_code: str, reasons: list[str]) -> None:
    try:
        tree = ast.parse(vulnerable_code)
    except SyntaxError:
        return
    _require(
        _matches_application_type(spec.application_type, vulnerable_code),
        f"vulnerable code does not match requested application type: {spec.application_type}",
        reasons,
    )
    _require(
        _matches_structure(spec.structure, tree),
        f"vulnerable code does not match requested structure: {spec.structure}",
        reasons,
    )
    if spec.cwe_key == "sql":
        _require(
            _matches_sql_flow(spec.flow_pattern, tree),
            f"vulnerable code does not match requested SQL flow pattern: {spec.flow_pattern}",
            reasons,
        )


def _matches_application_type(application_type: str, code: str) -> bool:
    lowered = code.lower()
    is_flask = "flask" in lowered and _has_http_route(lowered)
    is_django = "django" in lowered and ("request" in lowered or "view" in lowered)
    if application_type == "Flask":
        return is_flask
    if application_type == "Django":
        return is_django
    if application_type == "API":
        return is_flask or ("fastapi" in lowered and _has_http_route(lowered))
    if application_type in {"CLI", "script"}:
        return not any(framework in lowered for framework in ("flask", "django", "fastapi")) and (
            "input(" in lowered or "sys.argv" in lowered or "argparse" in lowered
        )
    return False


def _has_http_route(code: str) -> bool:
    return any(
        marker in code
        for marker in (
            "@app.route",
            "@app.get",
            "@app.post",
            "@app.put",
            "@app.delete",
            "add_url_rule(",
            "@router.",
            "@blueprint.",
        )
    )


def _matches_structure(structure: str, tree: ast.AST) -> bool:
    function_count = sum(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) for node in ast.walk(tree))
    class_count = sum(isinstance(node, ast.ClassDef) for node in ast.walk(tree))
    if structure == "single_function":
        return function_count == 1 and class_count == 0
    if structure == "multi_function":
        return function_count >= 2
    if structure == "class_based":
        return class_count >= 1
    return False


def _matches_sql_flow(flow_pattern: str, tree: ast.AST) -> bool:
    scopes = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    flags = [(_scope_has_user_source(scope), _scope_has_dynamic_sql(scope), _scope_has_execute(scope)) for scope in scopes]
    source_scopes = {index for index, (has_source, _, _) in enumerate(flags) if has_source}
    dynamic_scopes = {index for index, (_, has_dynamic, _) in enumerate(flags) if has_dynamic}
    execute_scopes = {index for index, (_, _, has_execute) in enumerate(flags) if has_execute}
    if flow_pattern == "direct":
        return bool(source_scopes & dynamic_scopes & execute_scopes)
    if flow_pattern == "indirect":
        return any(source != execution for source in source_scopes for execution in dynamic_scopes & execute_scopes)
    if flow_pattern == "complex":
        return _has_complex_sql_flow(scopes, source_scopes)
    return False


def _has_complex_sql_flow(scopes: list[ast.AST], source_scopes: set[int]) -> bool:
    named_scopes = {
        _scope_name(scope): scope
        for scope in scopes
        if _scope_name(scope)
    }
    source_names = {_scope_name(scopes[index]) for index in source_scopes}
    source_names.discard("")
    builder_names = {
        name
        for name, scope in named_scopes.items()
        if _scope_returns_dynamic_query(scope)
    }
    executor_names = {
        name
        for name, scope in named_scopes.items()
        if _scope_executes_query_parameter(scope)
    }
    if not source_names or not builder_names or not executor_names:
        return False

    source_calls = {
        name: _scope_call_names(scope)
        for name, scope in named_scopes.items()
    }
    for orchestrator, calls in source_calls.items():
        for builder in builder_names:
            for executor in executor_names:
                if len({builder, executor}) != 2 or builder not in calls or executor not in calls:
                    continue
                if orchestrator in source_names or calls.intersection(source_names):
                    return True
                if any(orchestrator in source_calls.get(source, set()) for source in source_names):
                    return True
    return False


def _scope_name(scope: ast.AST) -> str:
    return scope.name if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) else ""


def _scope_call_names(scope: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(scope):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            names.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            names.add(node.func.attr)
    return names


def _scope_returns_dynamic_query(scope: ast.AST) -> bool:
    dynamic_names: set[str] = set()
    for node in ast.walk(scope):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        if not _is_dynamic_sql_expression(node.value):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        dynamic_names.update(target.id for target in targets if isinstance(target, ast.Name))
    for node in ast.walk(scope):
        if not isinstance(node, ast.Return) or node.value is None:
            continue
        if _is_dynamic_sql_expression(node.value):
            return True
        if isinstance(node.value, ast.Name) and node.value.id in dynamic_names:
            return True
    return False


def _is_dynamic_sql_expression(node: ast.AST) -> bool:
    source = ast.unparse(node).lower()
    has_sql = any(keyword in source for keyword in ("select ", "insert ", "update ", "delete "))
    dynamic = any(
        isinstance(item, ast.JoinedStr)
        or isinstance(item, ast.BinOp) and isinstance(item.op, (ast.Add, ast.Mod))
        or isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute) and item.func.attr == "format"
        for item in ast.walk(node)
    )
    return has_sql and dynamic


def _scope_executes_query_parameter(scope: ast.AST) -> bool:
    parameters = {
        argument.arg
        for argument in scope.args.args
    } if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) else set()
    for node in ast.walk(scope):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) or node.func.attr not in {"execute", "executemany"}:
            continue
        if node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in parameters:
            return True
    return False


def _scope_has_user_source(scope: ast.AST) -> bool:
    for node in ast.walk(scope):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "input":
            return True
        if isinstance(node, ast.Attribute) and _attribute_root_name(node) in {"request", "sys"}:
            return True
    return False


def _scope_has_dynamic_sql(scope: ast.AST) -> bool:
    source = ast.unparse(scope).lower()
    if not any(keyword in source for keyword in ("select ", "insert ", "update ", "delete ")):
        return False
    return any(
        isinstance(node, ast.JoinedStr)
        or isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod))
        or isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"
        for node in ast.walk(scope)
    )


def _scope_has_execute(scope: ast.AST) -> bool:
    return any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "executemany"} for node in ast.walk(scope))


def _attribute_root_name(node: ast.Attribute) -> str | None:
    value: ast.AST = node
    while isinstance(value, ast.Attribute):
        value = value.value
    return value.id if isinstance(value, ast.Name) else None


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
    if ".startswith(" in lowered:
        return False

    if "safe_join(" in lowered:
        return " is none" in lowered or "== none" in lowered

    resolves_paths = ".resolve(" in lowered or "os.path.realpath(" in lowered
    if not resolves_paths:
        return False
    if ".is_relative_to(" in lowered or ".relative_to(" in lowered:
        return True
    if ".parents" in lowered and any(token in lowered for token in (" not in ", " in ")):
        return True
    return "commonpath(" in lowered and any(token in lowered for token in ("==", "!="))


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
    if any(token in lowered for token in ("ast.literal_eval", "whitelist", "allowed_operations", "dispatch")):
        return True
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return False
    return any(
        isinstance(node, ast.Dict)
        and any(
            isinstance(value, ast.Attribute)
            and isinstance(value.value, ast.Name)
            and value.value.id == "operator"
            for value in node.values
        )
        for node in ast.walk(tree)
    )


def _has_xss(code: str) -> bool:
    lowered = code.lower()
    has_html_sink = any(token in lowered for token in ("render_template_string", "httpresponse(", "response("))
    has_dynamic_html = any(token in code for token in (" + ", "%", ".format(", "Markup(", 'f"', "f'"))
    return (
        has_html_sink
        and has_dynamic_html
        and "escape(" not in lowered
    )


def _has_xss_fix(code: str) -> bool:
    lowered = code.lower()
    return "escape(" in lowered or "format_html(" in lowered or "{{" in code or "render_template(" in lowered


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
