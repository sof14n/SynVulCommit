from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any, Protocol

from .cwe_registry import get_cwe
from .diff_utils import extract_changed_parts, make_unified_diff
from .spec_sampler import GenerationSpec


class GenerationError(RuntimeError):
    pass


@dataclass
class GeneratedCommit:
    commit_message: str
    filename: str
    vulnerable_code: str
    fixed_code: str
    diff: str
    badparts: list[str]
    goodparts: list[str]
    provider: str
    raw_response: dict[str, Any]

    def to_record_fields(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("raw_response", None)
        return data


class Provider(Protocol):
    name: str

    def generate(self, spec: GenerationSpec, prompt: str) -> dict[str, Any]:
        ...


def generate_commit(provider_name: str, spec: GenerationSpec, prompt: str) -> GeneratedCommit:
    provider = get_provider(provider_name)
    raw = provider.generate(spec, prompt)
    candidate = normalize_candidate(raw, provider.name)
    if not candidate.badparts:
        candidate.badparts = infer_vulnerable_lines(spec, candidate.vulnerable_code)
    if not candidate.goodparts:
        candidate.goodparts = infer_fixed_lines(spec, candidate.fixed_code)
    return candidate


def get_provider(provider_name: str) -> Provider:
    normalized = provider_name.lower().strip()
    if normalized == "mock":
        return MockProvider()
    if normalized == "openai_compatible":
        return OpenAICompatibleProvider()
    if normalized == "local_http":
        return LocalHTTPProvider()
    raise GenerationError(f"unknown provider '{provider_name}'. Use mock, openai_compatible, or local_http.")


def normalize_candidate(raw: dict[str, Any], provider_name: str) -> GeneratedCommit:
    required = ("commit_message", "vulnerable_code", "fixed_code")
    missing = [field for field in required if not str(raw.get(field, "")).strip()]
    if missing:
        raise GenerationError(f"provider returned missing fields: {', '.join(missing)}")

    filename = str(raw.get("filename") or "app.py").strip()
    if not filename.endswith(".py"):
        filename = f"{filename}.py"

    vulnerable_code = _normalize_code(str(raw["vulnerable_code"]))
    fixed_code = _normalize_code(str(raw["fixed_code"]))
    diff = make_unified_diff(vulnerable_code, fixed_code, filename)

    badparts, goodparts = extract_changed_parts(diff)
    explicit_bad = _string_list(raw.get("vulnerable_lines"))
    explicit_good = _string_list(raw.get("fixed_lines"))
    if explicit_bad and _all_lines_present(explicit_bad, vulnerable_code):
        badparts = explicit_bad
    if explicit_good and _all_lines_present(explicit_good, fixed_code):
        goodparts = explicit_good

    return GeneratedCommit(
        commit_message=str(raw["commit_message"]).strip(),
        filename=filename,
        vulnerable_code=vulnerable_code,
        fixed_code=fixed_code,
        diff=diff,
        badparts=badparts,
        goodparts=goodparts,
        provider=provider_name,
        raw_response=raw,
    )


def parse_candidate_text(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?", "", cleaned, flags=re.IGNORECASE).strip()
    cleaned = re.sub(r"```$", "", cleaned).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(cleaned[start : end + 1])
            except json.JSONDecodeError as exc:
                raise GenerationError(f"provider returned malformed JSON: {exc}; preview={cleaned[:500]!r}") from exc
        raise GenerationError(f"provider returned no JSON object; preview={cleaned[:500]!r}")


def _normalize_code(code: str) -> str:
    code = code.replace("\r\n", "\n").replace("\r", "\n").strip()
    return code + "\n"


def _string_list(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _all_lines_present(lines: list[str], code: str) -> bool:
    code_lines = {line.strip() for line in code.splitlines() if line.strip()}
    return all(line.strip() in code_lines for line in lines)


def infer_vulnerable_lines(spec: GenerationSpec, code: str) -> list[str]:
    lines = [line.strip() for line in code.splitlines() if line.strip()]
    if spec.cwe_key == "sql":
        return _matching_lines(lines, ("execute(", "SELECT", "INSERT", "UPDATE", "DELETE"))
    if spec.cwe_key == "command_injection":
        return _matching_lines(lines, ("shell=True", "os.system(", "subprocess.getoutput("))
    if spec.cwe_key == "directory_traversal":
        return _matching_lines(lines, ("open(", "send_file(", "os.path.join", "request.args", "input("))
    if spec.cwe_key == "open_redirect":
        return [line for line in lines if "redirect(" in line and not line.startswith(("from ", "import "))]
    if spec.cwe_key == "remote_code_execution":
        return _matching_lines(lines, ("eval(", "exec(", "compile("))
    if spec.cwe_key == "xss":
        return _matching_lines(lines, ("render_template_string", "Markup(", "return \"<", "return '<"))
    if spec.cwe_key == "xsrf":
        disabled = _matching_lines(lines, ("WTF_CSRF_ENABLED", "csrf.exempt"))
        if disabled:
            return disabled
        return [line for line in lines if "methods=" in line.lower() and "post" in line.lower()]
    return []


def infer_fixed_lines(spec: GenerationSpec, code: str) -> list[str]:
    lines = [line.strip() for line in code.splitlines() if line.strip()]
    if spec.cwe_key == "sql":
        return [line for line in lines if "execute(" in line and ("?" in line or "%s" in line or ", (" in line)]
    if spec.cwe_key == "command_injection":
        return [line for line in lines if "subprocess.run([" in line or "shell=False" in line]
    if spec.cwe_key == "directory_traversal":
        return _matching_lines(lines, (".resolve()", "commonpath", "safe_join", "parents", "relative_to"))
    if spec.cwe_key == "open_redirect":
        return _matching_lines(lines, ("urlparse", "netloc", "scheme", "allowed", "startswith"))
    if spec.cwe_key == "remote_code_execution":
        return _matching_lines(lines, ("ast.literal_eval", "literal_eval", "whitelist", "dispatch"))
    if spec.cwe_key == "xss":
        return _matching_lines(lines, ("escape(", "{{", "render_template("))
    if spec.cwe_key == "xsrf":
        return _matching_lines(lines, ("CSRFProtect", "csrf_protect", "csrfmiddlewaretoken", "WTF_CSRF_ENABLED"))
    return []


def _matching_lines(lines: list[str], markers: tuple[str, ...]) -> list[str]:
    return [line for line in lines if any(marker.lower() in line.lower() for marker in markers)]


class MockProvider:
    name = "mock"

    def generate(self, spec: GenerationSpec, prompt: str) -> dict[str, Any]:
        del prompt
        samples = {
            "sql": _mock_sql,
            "command_injection": _mock_command_injection,
            "directory_traversal": _mock_directory_traversal,
            "open_redirect": _mock_open_redirect,
            "remote_code_execution": _mock_remote_code_execution,
            "xss": _mock_xss,
            "xsrf": _mock_xsrf,
        }
        try:
            return samples[spec.cwe_key]()
        except KeyError as exc:
            raise GenerationError(f"no mock sample for {spec.cwe_key}") from exc


class OpenAICompatibleProvider:
    name = "openai_compatible"

    def generate(self, spec: GenerationSpec, prompt: str) -> dict[str, Any]:
        del spec
        base_url = os.environ.get("SYNVUL_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        api_key = os.environ.get("SYNVUL_API_KEY")
        model = os.environ.get("SYNVUL_MODEL")
        if not api_key:
            raise GenerationError("SYNVUL_API_KEY is required for openai_compatible provider")
        if not model:
            raise GenerationError("SYNVUL_MODEL is required for openai_compatible provider")

        url = f"{base_url}/chat/completions"
        payload = {
            "model": model,
            "temperature": float(os.environ.get("SYNVUL_TEMPERATURE", "0.7")),
            "messages": [
                {
                    "role": "system",
                    "content": "You generate strict JSON for defensive Python security dataset construction.",
                },
                {"role": "user", "content": prompt},
            ],
        }
        response = _post_json(url, payload, {"Authorization": f"Bearer {api_key}"})
        text = _extract_text(response)
        return parse_candidate_text(text)


class LocalHTTPProvider:
    name = "local_http"

    def generate(self, spec: GenerationSpec, prompt: str) -> dict[str, Any]:
        del spec
        url = os.environ.get("SYNVUL_LOCAL_URL")
        if not url:
            raise GenerationError("SYNVUL_LOCAL_URL is required for local_http provider")
        model = os.environ.get("SYNVUL_LOCAL_MODEL")
        payload: dict[str, Any] = {
            "prompt": prompt,
            "stream": False,
            "messages": [{"role": "user", "content": prompt}],
            "options": {
                "temperature": float(os.environ.get("SYNVUL_TEMPERATURE", "0.2")),
                "num_predict": int(os.environ.get("SYNVUL_NUM_PREDICT", "4096")),
            },
        }
        response_format = os.environ.get("SYNVUL_LOCAL_FORMAT", "json").strip()
        if response_format:
            payload["format"] = response_format
        if model:
            payload["model"] = model
        headers: dict[str, str] = {}
        token = os.environ.get("SYNVUL_LOCAL_AUTH")
        if token:
            headers["Authorization"] = token
        response = _post_json(url, payload, headers)
        text = _extract_text(response)
        return parse_candidate_text(text)


def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise GenerationError(f"provider HTTP {exc.code}: {body[:500]}") from exc
    except urllib.error.URLError as exc:
        raise GenerationError(f"provider request failed: {exc}") from exc
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise GenerationError(f"provider returned non-JSON response: {body[:500]}") from exc


def _extract_text(response: dict[str, Any]) -> str:
    if "choices" in response:
        choice = response["choices"][0]
        if "message" in choice:
            return str(choice["message"].get("content", ""))
        if "text" in choice:
            return str(choice["text"])
    for key in ("output_text", "response", "generated_text", "text", "content"):
        if key in response:
            return str(response[key])
    if "output" in response and isinstance(response["output"], list):
        chunks: list[str] = []
        for item in response["output"]:
            for content in item.get("content", []):
                if "text" in content:
                    chunks.append(str(content["text"]))
        if chunks:
            return "\n".join(chunks)
    raise GenerationError(f"could not extract text from provider response keys: {sorted(response.keys())}")


def _mock_sql() -> dict[str, Any]:
    return {
        "commit_message": "Fix SQL injection in account lookup",
        "filename": "app.py",
        "vulnerable_code": """
import sqlite3
from flask import Flask, request

app = Flask(__name__)


def find_account(username):
    db = sqlite3.connect("accounts.db")
    cursor = db.cursor()
    query = f"SELECT id, email FROM accounts WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()


@app.get("/account")
def account():
    username = request.args.get("username", "")
    return {"accounts": find_account(username)}
""",
        "fixed_code": """
import sqlite3
from flask import Flask, request

app = Flask(__name__)


def find_account(username):
    db = sqlite3.connect("accounts.db")
    cursor = db.cursor()
    cursor.execute("SELECT id, email FROM accounts WHERE username = ?", (username,))
    return cursor.fetchall()


@app.get("/account")
def account():
    username = request.args.get("username", "")
    return {"accounts": find_account(username)}
""",
        "vulnerable_lines": ["query = f\"SELECT id, email FROM accounts WHERE username = '{username}'\"", "cursor.execute(query)"],
        "fixed_lines": ["cursor.execute(\"SELECT id, email FROM accounts WHERE username = ?\", (username,))"],
    }


def _mock_command_injection() -> dict[str, Any]:
    return {
        "commit_message": "Avoid shell execution in ping helper",
        "filename": "tools/ping_host.py",
        "vulnerable_code": """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.get("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    result = subprocess.run("ping -n 1 " + host, shell=True, capture_output=True, text=True)
    return result.stdout
""",
        "fixed_code": """
import ipaddress
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.get("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    ipaddress.ip_address(host)
    result = subprocess.run(["ping", "-n", "1", host], shell=False, capture_output=True, text=True)
    return result.stdout
""",
        "vulnerable_lines": ['result = subprocess.run("ping -n 1 " + host, shell=True, capture_output=True, text=True)'],
        "fixed_lines": ['result = subprocess.run(["ping", "-n", "1", host], shell=False, capture_output=True, text=True)'],
    }


def _mock_directory_traversal() -> dict[str, Any]:
    return {
        "commit_message": "Constrain report downloads to reports directory",
        "filename": "reports/download.py",
        "vulnerable_code": """
import os
from flask import Flask, request

app = Flask(__name__)
BASE_DIR = "reports"


@app.get("/download")
def download():
    name = request.args.get("file", "")
    path = os.path.join(BASE_DIR, name)
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()
""",
        "fixed_code": """
from pathlib import Path
from flask import Flask, abort, request

app = Flask(__name__)
BASE_DIR = Path("reports").resolve()


@app.get("/download")
def download():
    name = request.args.get("file", "")
    requested = (BASE_DIR / name).resolve()
    if BASE_DIR not in requested.parents and requested != BASE_DIR:
        abort(400)
    with requested.open("r", encoding="utf-8") as handle:
        return handle.read()
""",
        "vulnerable_lines": ['path = os.path.join(BASE_DIR, name)', 'with open(path, "r", encoding="utf-8") as handle:'],
        "fixed_lines": ["requested = (BASE_DIR / name).resolve()", "if BASE_DIR not in requested.parents and requested != BASE_DIR:"],
    }


def _mock_open_redirect() -> dict[str, Any]:
    return {
        "commit_message": "Validate redirect target before login redirect",
        "filename": "web/login.py",
        "vulnerable_code": """
from flask import Flask, redirect, request

app = Flask(__name__)


@app.get("/login")
def login():
    target = request.args.get("next", "/")
    return redirect(target)
""",
        "fixed_code": """
from urllib.parse import urlparse
from flask import Flask, redirect, request

app = Flask(__name__)


def local_redirect_target(target):
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        return "/"
    return target if target.startswith("/") else "/"


@app.get("/login")
def login():
    target = request.args.get("next", "/")
    return redirect(local_redirect_target(target))
""",
        "vulnerable_lines": ["return redirect(target)"],
        "fixed_lines": ["return redirect(local_redirect_target(target))"],
    }


def _mock_remote_code_execution() -> dict[str, Any]:
    return {
        "commit_message": "Replace eval-based calculator with safe parser",
        "filename": "api/calculator.py",
        "vulnerable_code": """
from flask import Flask, request

app = Flask(__name__)


@app.get("/calc")
def calculate():
    expression = request.args.get("expr", "0")
    return {"result": eval(expression)}
""",
        "fixed_code": """
import ast
from flask import Flask, request

app = Flask(__name__)


@app.get("/calc")
def calculate():
    expression = request.args.get("expr", "0")
    value = ast.literal_eval(expression)
    if not isinstance(value, (int, float)):
        return {"error": "number required"}, 400
    return {"result": value}
""",
        "vulnerable_lines": ["return {\"result\": eval(expression)}"],
        "fixed_lines": ["value = ast.literal_eval(expression)"],
    }


def _mock_xss() -> dict[str, Any]:
    return {
        "commit_message": "Escape profile name before rendering greeting",
        "filename": "web/profile.py",
        "vulnerable_code": """
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.get("/profile")
def profile():
    name = request.args.get("name", "guest")
    return render_template_string("<h1>Hello " + name + "</h1>")
""",
        "fixed_code": """
from markupsafe import escape
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.get("/profile")
def profile():
    name = request.args.get("name", "guest")
    safe_name = escape(name)
    return render_template_string("<h1>Hello {{ name }}</h1>", name=safe_name)
""",
        "vulnerable_lines": ['return render_template_string("<h1>Hello " + name + "</h1>")'],
        "fixed_lines": ['return render_template_string("<h1>Hello {{ name }}</h1>", name=safe_name)'],
    }


def _mock_xsrf() -> dict[str, Any]:
    return {
        "commit_message": "Enable CSRF protection for transfer route",
        "filename": "web/transfer.py",
        "vulnerable_code": """
from flask import Flask, request

app = Flask(__name__)
app.config["WTF_CSRF_ENABLED"] = False


@app.post("/transfer")
def transfer():
    amount = request.form.get("amount", "0")
    destination = request.form.get("destination", "")
    return {"sent": amount, "to": destination}
""",
        "fixed_code": """
from flask import Flask, request
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config["WTF_CSRF_ENABLED"] = True
csrf = CSRFProtect(app)


@app.post("/transfer")
def transfer():
    amount = request.form.get("amount", "0")
    destination = request.form.get("destination", "")
    return {"sent": amount, "to": destination}
""",
        "vulnerable_lines": ['app.config["WTF_CSRF_ENABLED"] = False'],
        "fixed_lines": ['app.config["WTF_CSRF_ENABLED"] = True', "csrf = CSRFProtect(app)"],
    }
