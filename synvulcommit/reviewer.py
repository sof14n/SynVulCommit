from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Any

from .llm_generator import GeneratedCommit, GenerationError, get_provider
from .spec_sampler import GenerationSpec


REVIEW_VERDICTS = {"pass", "fail", "unsure"}
REASON_CATEGORIES = {"none", "wrong_cwe", "incomplete_fix", "wrong_context", "runtime_issue", "other"}
REVIEW_FIELDS = {
    "verdict",
    "cwe_correct",
    "fix_correct",
    "context_correct",
    "runtime_plausible",
    "reason_category",
}
REVIEW_SYSTEM_PROMPT = "You are a strict, independent reviewer of defensive Python vulnerability dataset records."


@dataclass(frozen=True)
class ReviewResult:
    verdict: str
    cwe_correct: bool
    fix_correct: bool
    context_correct: bool
    runtime_plausible: bool
    reason_category: str
    provider: str
    model: str | None

    @property
    def passed(self) -> bool:
        return self.verdict == "pass"

    def to_dict(self) -> dict[str, Any]:
        return {"required": True, "status": "completed", **asdict(self)}


def review_candidate(
    provider_name: str,
    spec: GenerationSpec,
    candidate: GeneratedCommit,
    reviewer_profile: bool = False,
) -> ReviewResult:
    provider = get_provider(provider_name, reviewer_profile=reviewer_profile)
    raw = provider.complete_json(
        REVIEW_SYSTEM_PROMPT,
        build_review_prompt(spec, candidate),
        max_tokens=_review_max_tokens(),
    )
    return parse_review_result(raw, provider.name, _provider_model(provider_name, reviewer_profile))


def build_review_prompt(spec: GenerationSpec, candidate: GeneratedCommit) -> str:
    return f"""Review this generated Python security-fix pair without rewriting it.

Expected specification:
- CWE: {spec.cwe} ({spec.cwe_name})
- Application type: {spec.application_type}
- Flow pattern: {spec.flow_pattern}
- Structure: {spec.structure}
- Difficulty: {spec.difficulty}

Vulnerable code:
--- vulnerable.py ---
{candidate.vulnerable_code.rstrip()}
--- end vulnerable.py ---

Fixed code:
--- fixed.py ---
{candidate.fixed_code.rstrip()}
--- end fixed.py ---

Reject the pair if either version introduces another SynVulCommit CWE beyond the requested one. If the fixed code retains or introduces another CWE, set fix_correct to false. For either case, set cwe_correct to false and use reason_category "wrong_cwe".

Return only this JSON object, with no Markdown, explanation, source code, or additional fields:
{{
  "verdict": "pass" | "fail" | "unsure",
  "cwe_correct": true | false,
  "fix_correct": true | false,
  "context_correct": true | false,
  "runtime_plausible": true | false,
  "reason_category": "none" | "wrong_cwe" | "incomplete_fix" | "wrong_context" | "runtime_issue" | "other"
}}

Use verdict "pass" only when every boolean is true and reason_category is "none". For "fail" or "unsure", use a non-"none" reason_category."""


def parse_review_result(raw: Any, provider: str, model: str | None) -> ReviewResult:
    if not isinstance(raw, dict) or set(raw) != REVIEW_FIELDS:
        raise GenerationError("reviewer returned an invalid review schema")
    verdict = raw.get("verdict")
    category = raw.get("reason_category")
    boolean_fields = ("cwe_correct", "fix_correct", "context_correct", "runtime_plausible")
    if not isinstance(verdict, str) or verdict not in REVIEW_VERDICTS:
        raise GenerationError("reviewer returned an invalid verdict")
    if not isinstance(category, str) or category not in REASON_CATEGORIES:
        raise GenerationError("reviewer returned an invalid reason category")
    if any(type(raw[field]) is not bool for field in boolean_fields):
        raise GenerationError("reviewer returned non-boolean assessment fields")
    assessments = [raw[field] for field in boolean_fields]
    if verdict == "pass" and (not all(assessments) or category != "none"):
        raise GenerationError("reviewer returned an inconsistent pass verdict")
    if verdict != "pass" and category == "none":
        raise GenerationError("reviewer returned an inconsistent non-pass verdict")
    return ReviewResult(
        verdict=verdict,
        cwe_correct=raw["cwe_correct"],
        fix_correct=raw["fix_correct"],
        context_correct=raw["context_correct"],
        runtime_plausible=raw["runtime_plausible"],
        reason_category=category,
        provider=provider,
        model=model,
    )


def review_error(provider_name: str, reviewer_profile: bool) -> dict[str, Any]:
    return {
        "required": True,
        "status": "error",
        "provider": provider_name,
        "model": _provider_model(provider_name, reviewer_profile),
    }


def review_not_run(required: bool) -> dict[str, Any]:
    return {
        "required": required,
        "status": "not_run" if required else "skipped",
    }


def validate_reviewer_configuration() -> None:
    _review_max_tokens()


def _review_max_tokens() -> int:
    raw_value = os.environ.get("SYNVUL_REVIEW_MAX_TOKENS", "512")
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise GenerationError("SYNVUL_REVIEW_MAX_TOKENS must be an integer") from exc
    if not 128 <= value <= 8192:
        raise GenerationError("SYNVUL_REVIEW_MAX_TOKENS must be between 128 and 8192")
    return value


def _provider_model(provider_name: str, reviewer_profile: bool) -> str | None:
    prefix = "SYNVUL_REVIEW_" if reviewer_profile else "SYNVUL_"
    normalized = provider_name.lower().strip()
    if normalized == "openai_compatible":
        return os.environ.get(f"{prefix}MODEL") or None
    if normalized == "local_http":
        return os.environ.get(f"{prefix}LOCAL_MODEL") or None
    return None
