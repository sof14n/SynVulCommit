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

from .cwe_registry import get_cwe
from .llm_generator import GeneratedCommit
from .spec_sampler import GenerationSpec
from .structural_checks import run_structural_checks


@dataclass
class ToolRun:
    name: str
    available: bool
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

        bandit_before = _run_bandit(before_path)
        bandit_after = _run_bandit(after_path)
        semgrep_before = _run_semgrep(before_path, rules_dir)
        semgrep_after = _run_semgrep(after_path, rules_dir)

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
        if after_ids.intersection(definition.semgrep_rule_ids):
            reasons.append(f"Semgrep still reports expected ids after fix: {', '.join(sorted(after_ids.intersection(definition.semgrep_rule_ids)))}")

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
    command = [sys.executable, "-m", "bandit", "-f", "json", "-q", str(path)]
    completed = _run_command(command)
    if completed["missing"]:
        return ToolRun("bandit", False, command, completed["returncode"], [], completed["error"])
    findings = _parse_bandit_findings(completed["stdout"])
    return ToolRun("bandit", True, command, completed["returncode"], findings, completed["error"])


def _run_semgrep(path: Path, rules_dir: Path) -> ToolRun:
    command = [
        sys.executable,
        "-m",
        "semgrep.console_scripts.pysemgrep",
        "--disable-version-check",
        "--metrics=off",
        "--json",
        "--quiet",
        "--config",
        str(rules_dir),
        str(path),
    ]
    config_home = path.parent / "semgrep_config"
    semgrep_data = config_home / ".semgrep"
    config_home.mkdir(parents=True, exist_ok=True)
    extra_env = {
        "XDG_CONFIG_HOME": str(config_home),
        "SEMGREP_LOG_FILE": str(semgrep_data / "semgrep.log"),
        "SEMGREP_SETTINGS_FILE": str(semgrep_data / "settings.yml"),
    }
    completed = _run_command(command, extra_env=extra_env)
    if completed["missing"]:
        return ToolRun("semgrep", False, command, completed["returncode"], [], completed["error"])
    findings = _parse_semgrep_findings(completed["stdout"])
    return ToolRun("semgrep", True, command, completed["returncode"], findings, completed["error"])


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
        return {"missing": True, "returncode": None, "stdout": "", "error": str(exc)}
    except subprocess.TimeoutExpired as exc:
        return {"missing": False, "returncode": None, "stdout": exc.stdout or "", "error": "tool timed out"}

    stderr = completed.stderr.strip()
    missing = "No module named bandit" in stderr or "not recognized" in stderr
    return {
        "missing": missing,
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


def _parse_bandit_findings(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    return list(data.get("results", []))


def _parse_semgrep_findings(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    return list(data.get("results", []))


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
    message = f"{label} is not available; install dependencies with: python -m pip install -r requirements.txt"
    if require_tools:
        reasons.append(message)
    else:
        warnings.append(message)
