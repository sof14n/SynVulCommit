from __future__ import annotations

import unittest

from synvulcommit.structural_checks import (
    _has_path_containment,
    _has_parameterized_sql,
    _has_rce_safe_replacement,
    _has_unserialized_django_query_response,
    _matches_application_type,
    run_structural_checks,
)
from synvulcommit.spec_sampler import GenerationSpec


class StructuralCheckTests(unittest.TestCase):
    def test_unknown_known_framework_import_is_rejected(self) -> None:
        spec = GenerationSpec("xss", "CWE-79", "Cross-Site Scripting", "xss", "Flask", "direct", "easy", "single_function", 0)
        vulnerable = (
            "from flask import Flask, Response, ify, request\n\n"
            "app = Flask(__name__)\n\n"
            "@app.route('/tag')\n"
            "def tag():\n"
            "    value = request.args.get('tag', '')\n"
            "    return Response('<h1>' + value + '</h1>')\n"
        )
        fixed = vulnerable.replace("ify, ", "")

        result = run_structural_checks(spec, vulnerable, fixed)

        self.assertFalse(result.passed)
        self.assertIn("vulnerable_code imports unknown symbol 'ify' from 'flask'", result.reasons)

    def test_standard_flask_url_for_import_is_accepted(self) -> None:
        spec = GenerationSpec("open_redirect", "CWE-601", "Open Redirect", "open_redirect", "Flask", "direct", "easy", "single_function", 0)
        code = (
            "from flask import Flask, redirect, request, url_for\n\n"
            "app = Flask(__name__)\n\n"
            "@app.route('/continue')\n"
            "def continue_to_next():\n"
            "    target = request.args.get('next', '/')\n"
            "    return redirect(target)\n"
        )

        result = run_structural_checks(spec, code, code)

        self.assertNotIn("vulnerable_code imports unknown symbol 'url_for' from 'flask'", result.reasons)

    def test_standard_flask_and_django_http_imports_are_accepted(self) -> None:
        spec = GenerationSpec("open_redirect", "CWE-601", "Open Redirect", "open_redirect", "Django", "direct", "easy", "single_function", 0)
        code = (
            "from django.http import HttpRequest, HttpResponseRedirect\n"
            "from flask import abort, send_file\n\n"
            "def continue_to_next(request: HttpRequest):\n"
            "    return HttpResponseRedirect('/home/')\n"
        )

        result = run_structural_checks(spec, code, code)

        self.assertFalse(any("imports unknown symbol" in reason for reason in result.reasons))

    def test_directory_containment_rejects_string_prefix_check(self) -> None:
        code = '''
from pathlib import Path

base = Path("/srv/data").resolve()
requested = (base / name).resolve()
if not str(requested).startswith(str(base)):
    raise ValueError("outside base")
'''

        self.assertFalse(_has_path_containment(code))

    def test_directory_containment_accepts_path_safe_strategies(self) -> None:
        strategies = (
            '''
from pathlib import Path
base = Path("/srv/data").resolve()
requested = (base / name).resolve()
if not requested.is_relative_to(base):
    raise ValueError("outside base")
''',
            '''
from pathlib import Path
base = Path("/srv/data").resolve()
requested = (base / name).resolve()
try:
    requested.relative_to(base)
except ValueError:
    raise ValueError("outside base")
''',
            '''
from pathlib import Path
base = Path("/srv/data").resolve()
requested = (base / name).resolve()
if base not in requested.parents and requested != base:
    raise ValueError("outside base")
''',
            '''
import os
base = os.path.realpath("/srv/data")
requested = os.path.realpath(os.path.join(base, name))
if os.path.commonpath([base, requested]) != base:
    raise ValueError("outside base")
''',
            '''
from werkzeug.utils import safe_join
requested = safe_join("/srv/data", name)
if requested is None:
    raise ValueError("outside base")
''',
        )

        for code in strategies:
            with self.subTest(code=code):
                self.assertTrue(_has_path_containment(code))

    def test_flask_add_url_rule_is_recognized_as_an_http_route(self) -> None:
        code = '''
from flask import Flask
from flask.views import MethodView

app = Flask(__name__)

class SubmitView(MethodView):
    def post(self):
        return "ok"

app.add_url_rule("/submit", view_func=SubmitView.as_view("submit"))
'''

        self.assertTrue(_matches_application_type("Flask", code))

    def test_named_sql_parameters_are_accepted(self) -> None:
        code = '''
cursor.execute(
    "SELECT id FROM users WHERE name = :name",
    {"name": username},
)
'''
        self.assertTrue(_has_parameterized_sql(code))

    def test_static_query_variable_with_bound_values_is_accepted(self) -> None:
        code = '''
query = "SELECT id FROM users WHERE name = ?"
cursor.execute(query, (username,))
'''
        self.assertTrue(_has_parameterized_sql(code))

    def test_dynamic_query_variable_with_bound_values_is_not_accepted(self) -> None:
        code = '''
query = f"SELECT id FROM users WHERE name = '{username}'"
cursor.execute(query, (username,))
'''
        self.assertFalse(_has_parameterized_sql(code))

    def test_static_query_builder_helpers_are_accepted_but_dynamic_helpers_are_not(self) -> None:
        safe_tuple_return = '''
def build_query(username):
    return "SELECT id FROM users WHERE name = ?", (username,)

def execute_query(query, params):
    cursor.execute(query, params)

query, params = build_query(username)
execute_query(query, params)
'''
        safe_direct_return = '''
def build_query():
    return "SELECT id FROM users WHERE name = ?"

cursor.execute(build_query(), (username,))
'''
        unsafe_dynamic_return = '''
def build_query(username):
    return f"SELECT id FROM users WHERE name = '{username}'", (username,)

query, params = build_query(username)
cursor.execute(query, params)
'''

        self.assertTrue(_has_parameterized_sql(safe_tuple_return))
        self.assertTrue(_has_parameterized_sql(safe_direct_return))
        self.assertFalse(_has_parameterized_sql(unsafe_dynamic_return))

    def test_static_query_and_values_passed_to_execution_helper_are_accepted(self) -> None:
        code = '''
def build_query():
    return "SELECT id FROM users WHERE name = ?"

def execute_query(query, params):
    cursor.execute(query, params)

query = build_query()
execute_query(query, (username,))
'''

        self.assertTrue(_has_parameterized_sql(code))

    def test_django_raw_sql_requires_percent_s_placeholders(self) -> None:
        question_mark_code = '''
cursor.execute("SELECT id FROM users WHERE name = ?", [username])
'''
        django_code = '''
cursor.execute("SELECT id FROM users WHERE name = %s", [username])
'''

        self.assertFalse(_has_parameterized_sql(question_mark_code, "Django"))
        self.assertTrue(_has_parameterized_sql(django_code, "Django"))

    def test_django_query_rows_must_be_serialized_before_response(self) -> None:
        unsafe = '''
row = cursor.fetchone()
return JsonResponse({"user": row})
'''
        safe = '''
row = cursor.fetchone()
return JsonResponse({"user": list(row) if row else None})
'''

        self.assertTrue(_has_unserialized_django_query_response(unsafe))
        self.assertFalse(_has_unserialized_django_query_response(safe))

    def test_sql_context_requires_the_requested_framework_structure_and_flow(self) -> None:
        spec = GenerationSpec("sql", "CWE-89", "SQL Injection", "sql", "Flask", "direct", "easy", "single_function", 0)
        vulnerable = '''
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.get("/user")
def get_user():
    username = request.args.get("username", "")
    cursor = sqlite3.connect("users.db").cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchone()
'''
        fixed = vulnerable.replace(
            'cursor.execute(f"SELECT * FROM users WHERE username = \'{username}\'")',
            'cursor.execute("SELECT * FROM users WHERE username = ?", (username,))',
        )

        result = run_structural_checks(spec, vulnerable, fixed)

        self.assertTrue(result.passed, result.reasons)

    def test_sql_context_rejects_a_bare_api_class(self) -> None:
        spec = GenerationSpec("sql", "CWE-89", "SQL Injection", "sql", "API", "direct", "easy", "single_function", 0)
        vulnerable = '''
import sqlite3

def get_user():
    username = input()
    cursor = sqlite3.connect("users.db").cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchone()
'''
        fixed = vulnerable.replace(
            'cursor.execute(f"SELECT * FROM users WHERE username = \'{username}\'")',
            'cursor.execute("SELECT * FROM users WHERE username = ?", (username,))',
        )

        result = run_structural_checks(spec, vulnerable, fixed)

        self.assertIn("vulnerable code does not match requested application type: API", result.reasons)

    def test_complex_sql_context_requires_linked_source_builder_and_executor(self) -> None:
        spec = GenerationSpec("sql", "CWE-89", "SQL Injection", "sql", "Flask", "complex", "easy", "multi_function", 0)
        vulnerable = '''
import sqlite3
from flask import Flask, request

app = Flask(__name__)

def build_query(username):
    return f"SELECT * FROM users WHERE username = '{username}'"

def execute_query(query):
    cursor = sqlite3.connect("users.db").cursor()
    return cursor.execute(query).fetchall()

@app.get("/user")
def get_user():
    username = request.args.get("username", "")
    return str(execute_query(build_query(username)))
'''
        fixed = vulnerable.replace(
            'def build_query(username):\n    return f"SELECT * FROM users WHERE username = \'{username}\'"\n\n',
            "",
        ).replace(
            "def execute_query(query):\n    cursor = sqlite3.connect(\"users.db\").cursor()\n    return cursor.execute(query).fetchall()",
            "def execute_query(username):\n    cursor = sqlite3.connect(\"users.db\").cursor()\n    return cursor.execute(\"SELECT * FROM users WHERE username = ?\", (username,)).fetchall()",
        ).replace("execute_query(build_query(username))", "execute_query(username)")

        result = run_structural_checks(spec, vulnerable, fixed)

        self.assertTrue(result.passed, result.reasons)

    def test_complex_sql_context_rejects_unlinked_query_and_execute_in_one_helper(self) -> None:
        spec = GenerationSpec("sql", "CWE-89", "SQL Injection", "sql", "Flask", "complex", "easy", "class_based", 0)
        vulnerable = '''
import sqlite3
from flask import Flask, request

app = Flask(__name__)

class Database:
    def get_user(self, username):
        query = f"SELECT * FROM users WHERE username = '{username}'"
        return sqlite3.connect("users.db").execute(query).fetchall()

@app.get("/user")
def get_user():
    username = request.args.get("username", "")
    return str(Database().get_user(username))
'''
        fixed = vulnerable.replace(
            'query = f"SELECT * FROM users WHERE username = \'{username}\'"\n        return sqlite3.connect("users.db").execute(query).fetchall()',
            'return sqlite3.connect("users.db").execute("SELECT * FROM users WHERE username = ?", (username,)).fetchall()',
        )

        result = run_structural_checks(spec, vulnerable, fixed)

        self.assertIn("vulnerable code does not match requested SQL flow pattern: complex", result.reasons)

    def test_validated_operator_dispatch_is_accepted_for_rce_fix(self) -> None:
        code = '''
import operator
import re

operations = {"+": operator.add}
match = re.match(r"^(\\d+)\\s*([+])\\s*(\\d+)$", expression)
if not match:
    raise ValueError("invalid expression")
return operations[match.group(2)](int(match.group(1)), int(match.group(3)))
'''
        self.assertTrue(_has_rce_safe_replacement(code))

    def test_tokenized_operator_dispatch_is_accepted_for_rce_fix(self) -> None:
        code = '''
import operator
import re

operations = {"+": operator.add}
tokens = re.findall(r"\\d+|[+]", expression)
return operations[tokens[1]](int(tokens[0]), int(tokens[2]))
'''
        self.assertTrue(_has_rce_safe_replacement(code))

    def test_named_operator_dispatch_map_is_accepted_for_rce_fix(self) -> None:
        code = '''
import operator

allowed_ops = {
    "+": operator.add,
    "-": operator.sub,
}

def calculate(symbol, left, right):
    if symbol not in allowed_ops:
        raise ValueError("unsupported operator")
    return allowed_ops[symbol](left, right)
'''
        self.assertTrue(_has_rce_safe_replacement(code))


if __name__ == "__main__":
    unittest.main()
