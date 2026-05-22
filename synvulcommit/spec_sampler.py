from __future__ import annotations

import random
from dataclasses import asdict, dataclass
from itertools import cycle

from .cwe_registry import CWEDefinition, all_cwes


APP_TYPES = ("Flask", "Django", "CLI", "API", "script")
FLOW_PATTERNS = ("direct", "indirect", "complex")
DIFFICULTIES = ("easy", "medium", "hard")
STRUCTURES = ("single_function", "class_based", "multi_function")

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

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def make_spec(
    definition: CWEDefinition,
    sample_index: int,
    rng: random.Random,
) -> GenerationSpec:
    app_types = APP_TYPES_BY_CWE.get(definition.key, APP_TYPES)
    return GenerationSpec(
        cwe_key=definition.key,
        cwe=definition.cwe,
        cwe_name=definition.name,
        mode=definition.mode,
        application_type=rng.choice(app_types),
        flow_pattern=rng.choice(FLOW_PATTERNS),
        difficulty=rng.choice(DIFFICULTIES),
        structure=rng.choice(STRUCTURES),
        sample_index=sample_index,
    )


def iter_specs(per_cwe: int, seed: int | None = None) -> list[GenerationSpec]:
    rng = random.Random(seed)
    specs: list[GenerationSpec] = []
    for definition in all_cwes():
        for index in range(per_cwe):
            specs.append(make_spec(definition, index, rng))
    rng.shuffle(specs)
    return specs


def infinite_specs(seed: int | None = None):
    rng = random.Random(seed)
    counters = {definition.key: 0 for definition in all_cwes()}
    for definition in cycle(all_cwes()):
        index = counters[definition.key]
        counters[definition.key] = index + 1
        yield make_spec(definition, index, rng)
