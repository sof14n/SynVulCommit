from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DiversityIndex:
    fingerprints: set[str] = field(default_factory=set)
    code_hashes: set[str] = field(default_factory=set)

    def load_existing(self, records: list[dict[str, Any]]) -> None:
        for record in records:
            self.fingerprints.add(make_fingerprint(record))
            self.code_hashes.add(_hash_text(str(record.get("vulnerable_code", ""))))

    def accepts(self, record: dict[str, Any]) -> tuple[bool, str | None]:
        fingerprint = make_fingerprint(record)
        code_hash = _hash_text(str(record.get("vulnerable_code", "")))
        if code_hash in self.code_hashes:
            return False, "duplicate vulnerable_code hash"
        if fingerprint in self.fingerprints:
            return False, "duplicate structural fingerprint"
        self.fingerprints.add(fingerprint)
        self.code_hashes.add(code_hash)
        return True, None


def make_fingerprint(record: dict[str, Any]) -> str:
    code = str(record.get("vulnerable_code", ""))
    context = record.get("context", {})
    if not isinstance(context, dict):
        context = {}
    node_names = _ast_node_names(code)
    imports = _imports(code)
    line_bucket = min(len(code.splitlines()) // 20, 5)
    parts = [
        str(record.get("cwe", "")),
        str(context.get("application_type", "")),
        str(context.get("flow_pattern", "")),
        str(context.get("structure", "")),
        ",".join(imports),
        ",".join(node_names[:80]),
        str(line_bucket),
    ]
    return _hash_text("|".join(parts))


def _ast_node_names(code: str) -> list[str]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    return [type(node).__name__ for node in ast.walk(tree)]


def _imports(code: str) -> list[str]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    return sorted(imports)


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
