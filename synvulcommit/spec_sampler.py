from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import asdict, dataclass, field
from itertools import product
from typing import Any

from .cwe_registry import CWEDefinition, all_cwes
from .generation_profile import COMPACT_PROFILE, WINDOW_BALANCED_PROFILE, normalize_generation_profile


APP_TYPES = ("Flask", "Django", "CLI", "API", "script")
FLOW_PATTERNS = ("direct", "indirect", "complex")
DIFFICULTIES = ("easy", "medium", "hard")
STRUCTURES = ("single_function", "class_based", "multi_function")
CONTEXT_DIMENSIONS = ("application_type", "flow_pattern", "structure", "difficulty")

# A flow contract must be achievable by the selected program shape. Planning
# an impossible pair wastes every provider retry and biases coverage reports.
FLOW_PATTERNS_BY_STRUCTURE = {
    "single_function": ("direct",),
    "class_based": FLOW_PATTERNS,
    "multi_function": ("indirect", "complex"),
}

APP_TYPES_BY_CWE = {
    "sql": ("Flask", "Django", "API", "script"),
    "command_injection": APP_TYPES,
    "directory_traversal": ("Flask", "API", "CLI", "script"),
    "open_redirect": ("Flask", "Django", "API"),
    "remote_code_execution": APP_TYPES,
    "xss": ("Flask", "Django", "API"),
    "xsrf": ("Flask",),
}


@dataclass(frozen=True)
class GenerationSpec:
    cwe_key: str
    cwe: str
    cwe_name: str
    mode: str
    application_type: str
    flow_pattern: str
    difficulty: str
    structure: str
    sample_index: int
    generation_profile: str = COMPACT_PROFILE

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def context_tuple(self) -> tuple[str, str, str, str]:
        return (self.application_type, self.flow_pattern, self.structure, self.difficulty)


@dataclass
class CweCoverage:
    definition: CWEDefinition
    generation_profile: str
    compatible_tuples: tuple[tuple[str, str, str, str], ...]
    existing_counts: Counter[tuple[str, str, str, str]]
    planned_counts: Counter[tuple[str, str, str, str]]
    target_accepted: int
    existing_accepted: int
    accepted_counts: Counter[tuple[str, str, str, str]] = field(default_factory=Counter)
    rejected_attempts: int = 0
    unfilled: int = 0

    def mark_accepted(self, spec: GenerationSpec) -> None:
        self.accepted_counts[spec.context_tuple()] += 1

    def mark_rejected_attempt(self) -> None:
        self.rejected_attempts += 1

    def mark_unfilled(self) -> None:
        self.unfilled += 1

    @property
    def accepted_this_run(self) -> int:
        return sum(self.accepted_counts.values())

    @property
    def total_accepted(self) -> int:
        return self.existing_accepted + self.accepted_this_run

    @property
    def target_met(self) -> bool:
        return self.total_accepted >= self.target_accepted

    def summary(self) -> dict[str, Any]:
        combined = self.existing_counts + self.accepted_counts
        distributions = {
            "application_type": _marginal_counts(
                combined, 0, _values_from_tuples(self.compatible_tuples, 0, APP_TYPES_BY_CWE.get(self.definition.key, APP_TYPES))
            ),
            "flow_pattern": _marginal_counts(combined, 1, _values_from_tuples(self.compatible_tuples, 1, FLOW_PATTERNS)),
            "structure": _marginal_counts(combined, 2, _values_from_tuples(self.compatible_tuples, 2, STRUCTURES)),
            "difficulty": _marginal_counts(combined, 3, _values_from_tuples(self.compatible_tuples, 3, DIFFICULTIES)),
        }
        uncovered_values = {
            dimension: [value for value, count in counts.items() if count == 0]
            for dimension, counts in distributions.items()
        }
        uncovered_tuples = [_tuple_to_dict(item) for item in self.compatible_tuples if combined[item] == 0]
        tuple_counts = {
            _tuple_key(item): {
                "existing": self.existing_counts[item],
                "planned": self.planned_counts[item],
                "accepted": self.accepted_counts[item],
                "total": combined[item],
            }
            for item in self.compatible_tuples
        }
        return {
            "cwe": self.definition.cwe,
            "mode": self.definition.mode,
            "generation_profile": self.generation_profile,
            "target_accepted": self.target_accepted,
            "existing_accepted": self.existing_accepted,
            "planned": sum(self.planned_counts.values()),
            "accepted": self.accepted_this_run,
            "total_accepted": self.total_accepted,
            "target_met": self.target_met,
            "rejected": self.rejected_attempts,
            "rejected_attempts": self.rejected_attempts,
            "unfilled": self.unfilled,
            "distributions": distributions,
            "context_tuple_distribution": tuple_counts,
            "tuple_counts": tuple_counts,
            "uncovered_values": uncovered_values,
            "uncovered_tuples": uncovered_tuples,
        }


@dataclass
class CoveragePlan:
    specs: list[GenerationSpec]
    coverage_by_mode: dict[str, CweCoverage]
    matched: bool = True

    def mark_accepted(self, spec: GenerationSpec) -> None:
        self.coverage_by_mode[spec.mode].mark_accepted(spec)

    def mark_rejected_attempt(self, spec: GenerationSpec) -> None:
        self.coverage_by_mode[spec.mode].mark_rejected_attempt()

    def mark_unfilled(self, spec: GenerationSpec) -> None:
        self.coverage_by_mode[spec.mode].mark_unfilled()

    @property
    def has_unfilled(self) -> bool:
        return any(not coverage.target_met for coverage in self.coverage_by_mode.values())

    def summary(self) -> dict[str, Any]:
        return {mode: coverage.summary() for mode, coverage in sorted(self.coverage_by_mode.items())}


def build_coverage_plan(
    per_cwe: int,
    seed: int | None,
    existing_records: list[dict[str, Any]],
    cwe_filters: list[str] | None = None,
    generation_profile: str = COMPACT_PROFILE,
) -> CoveragePlan:
    if per_cwe < 0:
        raise ValueError("per_cwe must be non-negative")
    profile = normalize_generation_profile(generation_profile)
    wanted = {value.lower().strip() for value in cwe_filters or []}
    definitions = [
        definition
        for definition in all_cwes()
        if not wanted or definition.key in wanted or definition.mode in wanted or definition.cwe.lower() in wanted
    ]
    if cwe_filters and not definitions:
        return CoveragePlan([], {}, matched=False)

    coverage_by_mode: dict[str, CweCoverage] = {}
    specs: list[GenerationSpec] = []
    seed_value = 0 if seed is None else seed
    for definition in definitions:
        compatible_tuples = _compatible_tuples(definition, profile)
        existing_counts = _existing_tuple_counts(existing_records, definition, compatible_tuples, profile)
        existing_accepted = _accepted_record_count(existing_records, definition, profile)
        planned_counts = Counter(existing_counts)
        coverage = CweCoverage(
            definition,
            profile,
            compatible_tuples,
            existing_counts,
            Counter(),
            target_accepted=per_cwe,
            existing_accepted=existing_accepted,
        )
        start_index = _next_sample_index(existing_records, definition)
        for offset in range(max(0, per_cwe - existing_accepted)):
            context_tuple = _select_quota_tuple(
                compatible_tuples=compatible_tuples,
                counts=planned_counts,
                seed=seed_value,
                cwe_key=definition.key,
                slot=offset,
            )
            planned_counts[context_tuple] += 1
            coverage.planned_counts[context_tuple] += 1
            specs.append(_spec_from_tuple(definition, start_index + offset, context_tuple, profile))
        coverage_by_mode[definition.mode] = coverage

    specs.sort(key=lambda spec: _stable_tiebreak(seed_value, spec.cwe_key, spec.sample_index, spec.context_tuple()))
    return CoveragePlan(specs, coverage_by_mode)


def iter_specs(
    per_cwe: int,
    seed: int | None = None,
    existing_records: list[dict[str, Any]] | None = None,
    generation_profile: str = COMPACT_PROFILE,
) -> list[GenerationSpec]:
    return build_coverage_plan(per_cwe, seed, existing_records or [], generation_profile=generation_profile).specs


def make_spec(
    definition: CWEDefinition,
    sample_index: int,
    rng: Any = None,
    generation_profile: str = COMPACT_PROFILE,
) -> GenerationSpec:
    del rng
    profile = normalize_generation_profile(generation_profile)
    tuples = _compatible_tuples(definition, profile)
    return _spec_from_tuple(definition, sample_index, tuples[sample_index % len(tuples)], profile)


def _compatible_tuples(
    definition: CWEDefinition,
    generation_profile: str = COMPACT_PROFILE,
) -> tuple[tuple[str, str, str, str], ...]:
    structures = _structures_for_profile(generation_profile)
    return tuple(
        (application_type, flow_pattern, structure, difficulty)
        for application_type, structure, difficulty in product(
            APP_TYPES_BY_CWE.get(definition.key, APP_TYPES), structures, DIFFICULTIES
        )
        for flow_pattern in FLOW_PATTERNS_BY_STRUCTURE[structure]
    )


def _existing_tuple_counts(
    records: list[dict[str, Any]],
    definition: CWEDefinition,
    compatible_tuples: tuple[tuple[str, str, str, str], ...],
    generation_profile: str,
) -> Counter[tuple[str, str, str, str]]:
    valid = set(compatible_tuples)
    counts: Counter[tuple[str, str, str, str]] = Counter()
    for record in records:
        context = record.get("context")
        if not isinstance(context, dict):
            continue
        if not _record_matches_definition(record, definition):
            continue
        if _record_generation_profile(record) != generation_profile:
            continue
        context_tuple = (
            str(context.get("application_type", "")),
            str(context.get("flow_pattern", "")),
            str(context.get("structure", "")),
            str(context.get("difficulty", "")),
        )
        if context_tuple in valid:
            counts[context_tuple] += 1
    return counts


def _accepted_record_count(records: list[dict[str, Any]], definition: CWEDefinition, generation_profile: str) -> int:
    return sum(
        1
        for record in records
        if _record_matches_definition(record, definition)
        and _record_generation_profile(record) == generation_profile
    )


def _record_matches_definition(record: dict[str, Any], definition: CWEDefinition) -> bool:
    context = record.get("context")
    if not isinstance(context, dict):
        context = {}
    record_mode = str(record.get("mode") or context.get("mode", "")).lower()
    record_cwe = str(record.get("cwe") or context.get("cwe", "")).lower()
    record_key = str(context.get("cwe_key", "")).lower()
    return record_mode == definition.mode or record_cwe == definition.cwe.lower() or record_key == definition.key


def _record_generation_profile(record: dict[str, Any]) -> str:
    context = record.get("context")
    if not isinstance(context, dict):
        context = {}
    value = record.get("generation_profile") or context.get("generation_profile")
    try:
        return normalize_generation_profile(str(value) if value is not None else COMPACT_PROFILE)
    except ValueError:
        return COMPACT_PROFILE


def _next_sample_index(records: list[dict[str, Any]], definition: CWEDefinition) -> int:
    indexes: list[int] = []
    for record in records:
        context = record.get("context")
        if not isinstance(context, dict):
            continue
        if not _record_matches_definition(record, definition):
            continue
        try:
            indexes.append(int(context.get("sample_index")))
        except (TypeError, ValueError):
            continue
    return max(indexes, default=-1) + 1


def _select_quota_tuple(
    compatible_tuples: tuple[tuple[str, str, str, str], ...],
    counts: Counter[tuple[str, str, str, str]],
    seed: int,
    cwe_key: str,
    slot: int,
) -> tuple[str, str, str, str]:
    marginal_counts = [_marginal_counter(counts, index) for index in range(len(CONTEXT_DIMENSIONS))]
    return min(
        compatible_tuples,
        key=lambda item: (
            counts[item],
            marginal_counts[0][item[0]],
            marginal_counts[1][item[1]],
            marginal_counts[2][item[2]],
            marginal_counts[3][item[3]],
            _structure_flow_flexibility(item[2]),
            _stable_tiebreak(seed, cwe_key, slot, item),
        ),
    )


def _marginal_counter(counts: Counter[tuple[str, str, str, str]], index: int) -> Counter[str]:
    marginal: Counter[str] = Counter()
    for context_tuple, count in counts.items():
        if count:
            marginal[context_tuple[index]] += count
    return marginal


def _structure_flow_flexibility(structure: str) -> int:
    """Prefer less flexible structures when quota counts are otherwise tied."""
    return len(FLOW_PATTERNS_BY_STRUCTURE[structure])


def _marginal_counts(
    counts: Counter[tuple[str, str, str, str]],
    index: int,
    allowed_values: tuple[str, ...],
) -> dict[str, int]:
    marginal = _marginal_counter(counts, index)
    return {value: marginal[value] for value in allowed_values}


def _spec_from_tuple(
    definition: CWEDefinition,
    sample_index: int,
    context_tuple: tuple[str, str, str, str],
    generation_profile: str = COMPACT_PROFILE,
) -> GenerationSpec:
    application_type, flow_pattern, structure, difficulty = context_tuple
    return GenerationSpec(
        cwe_key=definition.key,
        cwe=definition.cwe,
        cwe_name=definition.name,
        mode=definition.mode,
        application_type=application_type,
        flow_pattern=flow_pattern,
        difficulty=difficulty,
        structure=structure,
        sample_index=sample_index,
        generation_profile=normalize_generation_profile(generation_profile),
    )


def _structures_for_profile(generation_profile: str) -> tuple[str, ...]:
    profile = normalize_generation_profile(generation_profile)
    if profile == WINDOW_BALANCED_PROFILE:
        return ("class_based", "multi_function")
    return STRUCTURES


def _values_from_tuples(
    compatible_tuples: tuple[tuple[str, str, str, str], ...],
    index: int,
    fallback: tuple[str, ...],
) -> tuple[str, ...]:
    values = tuple(value for value in fallback if any(item[index] == value for item in compatible_tuples))
    return values or fallback


def _stable_tiebreak(seed: int, cwe_key: str, slot: int, context_tuple: tuple[str, str, str, str]) -> str:
    value = "|".join((str(seed), cwe_key, str(slot), *context_tuple))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _tuple_key(context_tuple: tuple[str, str, str, str]) -> str:
    return "|".join(context_tuple)


def _tuple_to_dict(context_tuple: tuple[str, str, str, str]) -> dict[str, str]:
    return dict(zip(CONTEXT_DIMENSIONS, context_tuple, strict=True))
