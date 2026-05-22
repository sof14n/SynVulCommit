from __future__ import annotations

import ast
import hashlib
import io
import json
import keyword
import re
import tokenize
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


NEAR_DUPLICATE_THRESHOLD = 0.90
TOKEN_SHINGLE_SIZE = 5


@dataclass(frozen=True)
class DiversityEntry:
    sample_id: str
    cwe: str
    mode: str
    context: dict[str, Any]
    exact_pair_hash: str
    ast_fingerprint: str
    shingles: set[str]


@dataclass
class DiversityIndex:
    near_duplicate_threshold: float = NEAR_DUPLICATE_THRESHOLD
    shingle_size: int = TOKEN_SHINGLE_SIZE
    exact_pair_hashes: dict[str, DiversityEntry] = field(default_factory=dict)
    ast_fingerprints_by_bucket: dict[str, dict[str, DiversityEntry]] = field(default_factory=dict)
    entries_by_bucket: dict[str, list[DiversityEntry]] = field(default_factory=dict)
    rejection_counts: dict[str, int] = field(default_factory=dict)
    last_rejection: dict[str, Any] | None = None

    def load_existing(self, records: list[dict[str, Any]]) -> None:
        for record in records:
            self._add_entry(record)

    def accepts(self, record: dict[str, Any]) -> tuple[bool, str | None]:
        self.last_rejection = None
        entry = make_entry(record, self.shingle_size)
        bucket = entry.cwe or entry.mode

        exact_match = self.exact_pair_hashes.get(entry.exact_pair_hash)
        if exact_match is not None:
            return self._reject(
                reason="duplicate code pair hash",
                check="exact_code_pair",
                matched_entry=exact_match,
                fingerprint=entry.exact_pair_hash,
            )

        ast_match = self.ast_fingerprints_by_bucket.get(bucket, {}).get(entry.ast_fingerprint)
        if ast_match is not None:
            return self._reject(
                reason="duplicate normalized AST fingerprint",
                check="normalized_ast",
                matched_entry=ast_match,
                fingerprint=entry.ast_fingerprint,
            )

        for existing in self.entries_by_bucket.get(bucket, []):
            similarity = jaccard_similarity(entry.shingles, existing.shingles)
            if similarity >= self.near_duplicate_threshold:
                return self._reject(
                    reason=f"near-duplicate token shingles similarity {similarity:.3f}",
                    check="near_duplicate",
                    matched_entry=existing,
                    fingerprint=entry.exact_pair_hash,
                    similarity=similarity,
                )

        self._store_entry(entry)
        return True, None

    def summary(self) -> dict[str, Any]:
        entries = [entry for bucket_entries in self.entries_by_bucket.values() for entry in bucket_entries]
        return {
            "total_records": len(entries),
            "near_duplicate_threshold": self.near_duplicate_threshold,
            "token_shingle_size": self.shingle_size,
            "duplicate_rejections": dict(sorted(self.rejection_counts.items())),
            "distributions": {
                "cwe": _count_values(entry.cwe for entry in entries),
                "application_type": _count_context(entries, "application_type"),
                "flow_pattern": _count_context(entries, "flow_pattern"),
                "difficulty": _count_context(entries, "difficulty"),
                "structure": _count_context(entries, "structure"),
            },
        }

    def _add_entry(self, record: dict[str, Any]) -> None:
        self._store_entry(make_entry(record, self.shingle_size))

    def _store_entry(self, entry: DiversityEntry) -> None:
        bucket = entry.cwe or entry.mode
        self.exact_pair_hashes.setdefault(entry.exact_pair_hash, entry)
        self.ast_fingerprints_by_bucket.setdefault(bucket, {}).setdefault(entry.ast_fingerprint, entry)
        self.entries_by_bucket.setdefault(bucket, []).append(entry)

    def _reject(
        self,
        reason: str,
        check: str,
        matched_entry: DiversityEntry,
        fingerprint: str,
        similarity: float | None = None,
    ) -> tuple[bool, str]:
        self.rejection_counts[check] = self.rejection_counts.get(check, 0) + 1
        self.last_rejection = {
            "reason": reason,
            "check": check,
            "matched_id": matched_entry.sample_id,
            "matched_cwe": matched_entry.cwe,
            "matched_mode": matched_entry.mode,
            "fingerprint": fingerprint,
        }
        if similarity is not None:
            self.last_rejection["similarity"] = round(similarity, 6)
            self.last_rejection["threshold"] = self.near_duplicate_threshold
        return False, reason


def make_entry(record: dict[str, Any], shingle_size: int = TOKEN_SHINGLE_SIZE) -> DiversityEntry:
    context = record.get("context", {})
    if not isinstance(context, dict):
        context = {}
    return DiversityEntry(
        sample_id=str(record.get("id", "")),
        cwe=str(record.get("cwe", "")),
        mode=str(record.get("mode") or context.get("mode", "")),
        context=context,
        exact_pair_hash=make_code_pair_hash(record),
        ast_fingerprint=make_code_pair_ast_fingerprint(record),
        shingles=make_code_pair_shingles(record, shingle_size),
    )


def make_code_pair_hash(record: dict[str, Any]) -> str:
    vulnerable_code = _normalize_newlines(str(record.get("vulnerable_code", "")))
    fixed_code = _normalize_newlines(str(record.get("fixed_code", "")))
    return _hash_text(vulnerable_code + "\0" + fixed_code)


def make_code_pair_ast_fingerprint(record: dict[str, Any]) -> str:
    vulnerable = make_normalized_ast_fingerprint(str(record.get("vulnerable_code", "")))
    fixed = make_normalized_ast_fingerprint(str(record.get("fixed_code", "")))
    return _hash_text(vulnerable + "\0" + fixed)


def make_normalized_ast_fingerprint(code: str) -> str:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return _hash_text("syntax-error|" + _normalize_newlines(code))
    normalized = _AstNormalizer().visit(tree)
    ast.fix_missing_locations(normalized)
    return _hash_text(ast.dump(normalized, annotate_fields=True, include_attributes=False))


def make_code_pair_shingles(record: dict[str, Any], shingle_size: int = TOKEN_SHINGLE_SIZE) -> set[str]:
    tokens = _normalized_tokens(str(record.get("vulnerable_code", "")))
    tokens.append("<FIXED>")
    tokens.extend(_normalized_tokens(str(record.get("fixed_code", ""))))
    return _shingles(tokens, shingle_size)


def jaccard_similarity(left: set[str], right: set[str]) -> float:
    union = left | right
    if not union:
        return 0.0
    return len(left & right) / len(union)


def write_diversity_summary(summary: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class _AstNormalizer(ast.NodeTransformer):
    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        node.name = "FUNC"
        self.generic_visit(node)
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        node.name = "FUNC"
        self.generic_visit(node)
        return node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        node.name = "CLASS"
        self.generic_visit(node)
        return node

    def visit_arg(self, node: ast.arg) -> ast.AST:
        node.arg = "ARG"
        self.generic_visit(node)
        return node

    def visit_Name(self, node: ast.Name) -> ast.AST:
        node.id = "NAME"
        return node

    def visit_Attribute(self, node: ast.Attribute) -> ast.AST:
        self.generic_visit(node)
        node.attr = "ATTR"
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        node.value = _constant_marker(node.value)
        node.kind = None
        return node

    def visit_alias(self, node: ast.alias) -> ast.AST:
        node.name = "ALIAS"
        if node.asname:
            node.asname = "ALIAS"
        return node

    def visit_keyword(self, node: ast.keyword) -> ast.AST:
        self.generic_visit(node)
        if node.arg is not None:
            node.arg = "KW"
        return node

    def visit_Global(self, node: ast.Global) -> ast.AST:
        node.names = ["NAME" for _ in node.names]
        return node

    def visit_Nonlocal(self, node: ast.Nonlocal) -> ast.AST:
        node.names = ["NAME" for _ in node.names]
        return node

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> ast.AST:
        self.generic_visit(node)
        if node.name:
            node.name = "NAME"
        return node


def _constant_marker(value: Any) -> str:
    if value is None:
        return "NONE"
    if isinstance(value, bool):
        return "BOOL"
    if isinstance(value, (int, float, complex)):
        return "NUMBER"
    if isinstance(value, bytes):
        return "BYTES"
    if isinstance(value, str):
        return "STRING"
    return "CONSTANT"


def _normalized_tokens(code: str) -> list[str]:
    try:
        raw_tokens = tokenize.generate_tokens(io.StringIO(code).readline)
        tokens: list[str] = []
        for token in raw_tokens:
            if token.type in {
                tokenize.ENCODING,
                tokenize.ENDMARKER,
                tokenize.INDENT,
                tokenize.DEDENT,
                tokenize.NL,
                tokenize.NEWLINE,
                tokenize.COMMENT,
            }:
                continue
            if token.type == tokenize.NAME:
                tokens.append(token.string if keyword.iskeyword(token.string) else "NAME")
            elif token.type == tokenize.STRING:
                tokens.append("STRING")
            elif token.type == tokenize.NUMBER:
                tokens.append("NUMBER")
            else:
                tokens.append(token.string)
        return tokens
    except (tokenize.TokenError, IndentationError):
        return _fallback_tokens(code)


def _fallback_tokens(code: str) -> list[str]:
    return [token.lower() for token in re.findall(r"[A-Za-z_]+|\d+|[^\sA-Za-z_\d]", code)]


def _shingles(tokens: list[str], size: int) -> set[str]:
    if not tokens:
        return set()
    if len(tokens) < size:
        return {" ".join(tokens)}
    return {" ".join(tokens[index : index + size]) for index in range(0, len(tokens) - size + 1)}


def _count_values(values: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def _count_context(entries: list[DiversityEntry], key: str) -> dict[str, int]:
    return _count_values(entry.context.get(key) for entry in entries)


def _normalize_newlines(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n").strip()


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
