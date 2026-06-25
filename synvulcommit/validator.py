from __future__ import annotations

import json
import os
import shutil
import site
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .cwe_registry import all_semgrep_rule_ids, get_cwe
from .llm_generator import GeneratedCommit
from .spec_sampler import GenerationSpec
from .structural_checks import run_structural_checks


@dataclass
class ToolRun:
    name: str
    available: bool
    status: str
    command: list[str]
    returncode: int | None
    findings: list[dict[str, Any]]
    error: str | None


@dataclass
class ValidationResult:
    passed: bool
    reasons: list[str]
    warnings: list[str]
    structural: dict[str, Any]
    bandit_before: ToolRun
    bandit_after: ToolRun
    semgrep_before: ToolRun
    semgrep_after: ToolRun

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_candidate(
    spec: GenerationSpec,
    candidate: GeneratedCommit,
    rules_dir: Path,
    temp_root: Path,
    require_tools: bool = False,
) -> ValidationResult:
    definition = get_cwe(spec.cwe_key)
    reasons: list[str] = []
    warnings: list[str] = []
    if not candidate.badparts:
        reasons.append("candidate has no vulnerable badparts for VUDENC export")
    if not candidate.goodparts:
        reasons.append("candidate has no fixed goodparts for VUDENC export")
    structural_result = run_structural_checks(spec, candidate.vulnerable_code, candidate.fixed_code)
    if not structural_result.passed:
        reasons.extend(structural_result.reasons)

    temp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="synvulcommit_", dir=temp_root) as tmp:
        tmp_path = Path(tmp)
        before_path = tmp_path / "vulnerable.py"
        after_path = tmp_path / "fixed.py"
        before_path.write_text(candidate.vulnerable_code, encoding="utf-8")
        after_path.write_text(candidate.fixed_code, encoding="utf-8")

        bandit_before, bandit_after = _run_bandit_pair(before_path, after_path)
        semgrep_before, semgrep_after = _run_semgrep_pair(before_path, after_path, rules_dir)

    _handle_tool_availability("Bandit", bandit_before, bandit_after, require_tools, reasons, warnings)
    _handle_tool_availability("Semgrep", semgrep_before, semgrep_after, require_tools, reasons, warnings)

    if bandit_before.available and definition.bandit_ids:
        before_ids = _bandit_ids(bandit_before)
        after_ids = _bandit_ids(bandit_after)
        if not before_ids.intersection(definition.bandit_ids):
            warnings.append(f"Bandit did not report expected ids before fix: {', '.join(definition.bandit_ids)}")
        if after_ids.intersection(definition.bandit_ids):
            reasons.append(f"Bandit still reports expected ids after fix: {', '.join(sorted(after_ids.intersection(definition.bandit_ids)))}")

    if semgrep_before.available and definition.semgrep_rule_ids:
        before_ids = _semgrep_ids(semgrep_before)
        after_ids = _semgrep_ids(semgrep_after)
        if not before_ids.intersection(definition.semgrep_rule_ids):
            reasons.append(f"Semgrep did not report expected ids before fix: {', '.join(definition.semgrep_rule_ids)}")
        target_after_ids = after_ids.intersection(definition.semgrep_rule_ids)
        if (
            definition.key == "xss"
            and target_after_ids == {"synvul.cwe-79.xss-helper"}
            and structural_result.passed
        ):
            warnings.append("Semgrep XSS helper finding remained after a structurally verified escaping fix")
            target_after_ids.clear()
        if target_after_ids:
            reasons.append(f"Semgrep still reports expected ids after fix: {', '.join(sorted(target_after_ids))}")
        cross_cwe_after_ids = after_ids.intersection(all_semgrep_rule_ids()).difference(definition.semgrep_rule_ids)
        if cross_cwe_after_ids:
            reasons.append(
                "Semgrep reports other SynVulCommit rule ids after fix: "
                + ", ".join(sorted(cross_cwe_after_ids))
            )

    return ValidationResult(
        passed=not reasons,
        reasons=reasons,
        warnings=warnings,
        structural=asdict(structural_result),
        bandit_before=bandit_before,
        bandit_after=bandit_after,
        semgrep_before=semgrep_before,
        semgrep_after=semgrep_after,
    )


def _run_bandit(path: Path) -> ToolRun:
    return _run_bandit_paths([path])


def _run_bandit_pair(before_path: Path, after_path: Path) -> tuple[ToolRun, ToolRun]:
    combined = _run_bandit_paths([before_path, after_path])
    return _split_tool_run(combined, [before_path, after_path], ("filename",))


def _run_bandit_paths(paths: list[Path]) -> ToolRun:
    command = [sys.executable, "-m", "bandit", "-f", "json", "-q", *(str(path) for path in paths)]
    completed = _run_command(command)
    return _make_tool_run("bandit", command, completed, "results")


def _run_semgrep(path: Path, rules_dir: Path) -> ToolRun:
    return _run_semgrep_paths([path], rules_dir)


def _run_semgrep_pair(before_path: Path, after_path: Path, rules_dir: Path) -> tuple[ToolRun, ToolRun]:
    combined = _run_semgrep_paths([before_path, after_path], rules_dir)
    return _split_tool_run(combined, [before_path, after_path], ("path", "filename"))


def _run_semgrep_paths(paths: list[Path], rules_dir: Path) -> ToolRun:
    semgrep_command, scripts_dir = _find_semgrep()
    command = [
        semgrep_command,
        "--disable-version-check",
        "--metrics=off",
        "--json",
        "--quiet",
        "--config",
        str(rules_dir),
        *(str(path) for path in paths),
    ]
    config_home = paths[0].parent / "semgrep_config"
    semgrep_data = config_home / ".semgrep"
    config_home.mkdir(parents=True, exist_ok=True)
    extra_env = {
        "XDG_CONFIG_HOME": str(config_home),
        "SEMGREP_LOG_FILE": str(semgrep_data / "semgrep.log"),
        "SEMGREP_SETTINGS_FILE": str(semgrep_data / "settings.yml"),
    }
    if scripts_dir is not None:
        extra_env["PATH"] = str(scripts_dir) + ";" + os.environ.get("PATH", "")
    completed = _run_command(command, extra_env=extra_env)
    return _make_tool_run("semgrep", command, completed, "results")


def _split_tool_run(tool_run: ToolRun, paths: list[Path], finding_path_keys: tuple[str, ...]) -> tuple[ToolRun, ...]:
    return tuple(
        ToolRun(
            name=tool_run.name,
            available=tool_run.available,
            status=tool_run.status,
            command=tool_run.command,
            returncode=tool_run.returncode,
            findings=[
                finding
                for finding in tool_run.findings
                if _finding_matches_path(finding, path, finding_path_keys)
            ],
            error=tool_run.error,
        )
        for path in paths
    )


def _finding_matches_path(finding: dict[str, Any], path: Path, finding_path_keys: tuple[str, ...]) -> bool:
    for key in finding_path_keys:
        raw_path = finding.get(key)
        if not isinstance(raw_path, str) or not raw_path:
            continue
        candidate = Path(raw_path)
        try:
            if candidate.resolve() == path.resolve():
                return True
        except OSError:
            pass
        if candidate.name == path.name:
            return True
    return False


def _make_tool_run(
    name: str,
    command: list[str],
    completed: dict[str, Any],
    findings_key: str,
) -> ToolRun:
    status = str(completed["status"])
    if status != "completed":
        return ToolRun(name, False, status, command, completed["returncode"], [], completed["error"])

    findings, parse_error = _parse_findings(completed["stdout"], findings_key)
    if parse_error:
        message = _join_errors(completed["error"], parse_error)
        return ToolRun(name, False, "error", command, completed["returncode"], [], message)
    if completed["returncode"] not in {0, 1}:
        message = _join_errors(
            completed["error"],
            f"tool exited with unexpected status {completed['returncode']}",
        )
        return ToolRun(name, False, "error", command, completed["returncode"], findings, message)

    return ToolRun(name, True, "success", command, completed["returncode"], findings, completed["error"])


def _run_command(
    command: list[str],
    extra_path: Path | None = None,
    extra_env: dict[str, str] | None = None,
) -> dict[str, Any]:
    env = None
    if extra_path is not None or extra_env:
        env = os.environ.copy()
        if extra_path is not None:
            env["PATH"] = str(extra_path) + os.pathsep + env.get("PATH", "")
        if extra_env:
            env.update(extra_env)
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False, env=env)
    except FileNotFoundError as exc:
        return {"status": "missing", "returncode": None, "stdout": "", "error": str(exc)}
    except subprocess.TimeoutExpired as exc:
        return {"status": "timeout", "returncode": None, "stdout": exc.stdout or "", "error": "tool timed out"}

    stderr = completed.stderr.strip()
    status = "missing" if _is_missing_tool_error(stderr) else "completed"
    return {
        "status": status,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "error": stderr or None,
    }


def _find_semgrep() -> tuple[str, Path | None]:
    found = shutil.which("semgrep")
    if found:
        return found, None

    candidates: list[Path] = []
    user_base = Path(site.getuserbase())
    candidates.append(user_base / "Scripts")
    appdata = os.environ.get("APPDATA")
    if appdata:
        candidates.append(Path(appdata) / "Python" / f"Python{sys.version_info.major}{sys.version_info.minor}" / "Scripts")

    for scripts_dir in candidates:
        exe = scripts_dir / "semgrep.exe"
        if exe.exists():
            return str(exe), scripts_dir

    return "semgrep", None


def _parse_findings(stdout: str, findings_key: str) -> tuple[list[dict[str, Any]], str | None]:
    if not stdout.strip():
        return [], "tool returned no JSON output"
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        return [], f"tool returned invalid JSON: {exc.msg}"
    findings = data.get(findings_key)
    if not isinstance(findings, list):
        return [], f"tool JSON is missing a list-valued '{findings_key}' field"
    return [item for item in findings if isinstance(item, dict)], None


def _bandit_ids(result: ToolRun) -> set[str]:
    return {str(item.get("test_id", "")) for item in result.findings if item.get("test_id")}


def _semgrep_ids(result: ToolRun) -> set[str]:
    ids: set[str] = set()
    for item in result.findings:
        check_id = str(item.get("check_id", ""))
        if not check_id:
            continue
        ids.add(check_id)
        marker = ".synvul."
        if marker in check_id:
            ids.add("synvul." + check_id.split(marker, 1)[1])
    return ids


def _handle_tool_availability(
    label: str,
    before: ToolRun,
    after: ToolRun,
    require_tools: bool,
    reasons: list[str],
    warnings: list[str],
) -> None:
    if before.available and after.available:
        return
    statuses = {before.status, after.status}
    if "missing" in statuses:
        message = f"{label} is not available; install dependencies with: python -m pip install -r requirements.txt"
    elif "timeout" in statuses:
        message = f"{label} timed out while validating the candidate"
    else:
        details = _first_error(before.error, after.error)
        message = f"{label} failed to run correctly"
        if details:
            message = f"{message}: {details}"
    if require_tools:
        reasons.append(message)
    else:
        warnings.append(message)


def _is_missing_tool_error(stderr: str) -> bool:
    lowered = stderr.lower()
    return (
        "no module named" in lowered
        or "modulenotfounderror" in lowered
        or "is not recognized as the name of a cmdlet" in lowered
        or "not recognized as an internal or external command" in lowered
    )


def _join_errors(*messages: str | None) -> str | None:
    return "\n".join(message for message in messages if message) or None


def _first_error(*messages: str | None) -> str | None:
    for message in messages:
        if message:
            return message.splitlines()[-1][:240]
    return None
