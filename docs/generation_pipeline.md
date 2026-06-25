# Generation Pipeline

This document explains how SynVulCommit generates accepted vulnerable/fixed commit pairs.

## Pipeline Overview

Each generation run follows the same stages:

1. Plan quota slots for each CWE and context.
2. Ask a provider for a vulnerable/fixed Python pair.
3. Normalize the provider JSON into a commit candidate.
4. Run deterministic structural validation.
5. Run Bandit and Semgrep when available.
6. Run the second-stage LLM reviewer unless explicitly disabled.
7. Reject exact and near-duplicate vulnerable/fixed pairs.
8. Store accepted records in `samples.jsonl` and rejected attempts in `rejected.jsonl`.
9. Export VUDENC files and verify the dataset, unless `--no-export` is used.

The generator treats `--per-cwe` as the target accepted count per CWE. Existing accepted records in the selected output directory count toward the target, so rerunning a partial output resumes from the remaining deficit.

## Supported Modes

SynVulCommit covers the seven VUDENC-style vulnerability modes:

| Mode | CWE |
| --- | --- |
| `sql` | CWE-89 SQL Injection |
| `command_injection` | CWE-78 OS Command Injection |
| `directory_traversal` | CWE-22 Path Traversal |
| `open_redirect` | CWE-601 Open Redirect |
| `remote_code_execution` | CWE-94 Remote Code Execution |
| `xss` | CWE-79 Cross-Site Scripting |
| `xsrf` | CWE-352 Cross-Site Request Forgery |

## Quota Planning

Generation uses deterministic quota planning over four context dimensions:

- application type,
- flow pattern,
- difficulty,
- program structure.

The planner forms compatible context tuples for each CWE. It then chooses the next slot by lowest quota score:

1. full context tuple count,
2. application-type count,
3. flow-pattern count,
4. structure count,
5. difficulty count,
6. stable SHA-256 tie-breaker.

Rejected candidates retry the same planned slot. They are not replaced with random contexts. This makes the corpus easier to audit because failures are tied to specific planned coverage targets.

Each run writes `diversity_summary.json`, including planned, accepted, rejected, and unfilled counts per CWE; marginal context distributions; full tuple distributions; and uncovered values or tuples.

## Provider Configuration

Three provider types are supported:

- `mock`: deterministic local fixture provider for tests and parser checks.
- `openai_compatible`: chat-completions-style HTTP API.
- `local_http`: local model endpoint such as Ollama-compatible generation.

OpenAI-compatible generation reads:

```text
SYNVUL_BASE_URL
SYNVUL_API_KEY
SYNVUL_MODEL
SYNVUL_TEMPERATURE
SYNVUL_MAX_TOKENS
SYNVUL_REQUEST_TIMEOUT
SYNVUL_RESPONSE_FORMAT
```

For DeepSeek, use `SYNVUL_BASE_URL=https://api.deepseek.com` and set `SYNVUL_MODEL` to an enabled DeepSeek model. Secrets must stay in the environment or a local ignored `.env` file. They must not be committed.

Local HTTP generation reads:

```text
SYNVUL_LOCAL_URL
SYNVUL_LOCAL_MODEL
SYNVUL_LOCAL_AUTH
SYNVUL_LOCAL_FORMAT
```

## Deterministic Validation

The structural validator checks that a candidate actually matches the requested CWE and context. Examples:

- SQL vulnerable code must contain dynamic SQL execution, and fixed code must use static queries with placeholders and bound values.
- Command injection fixed code must avoid shell execution and use safe subprocess argument lists.
- Directory traversal fixed code must use path-aware containment such as resolved parent membership, `relative_to` / `is_relative_to`, component-aware `commonpath`, or safe join patterns.
- Open redirect fixed code must validate redirect targets.
- RCE fixed code must remove dynamic execution and use a safe parser or dispatch strategy.
- XSS fixed code must escape or template-render safely.
- XSRF fixed code must show CSRF protection or remove explicit CSRF disabling.

The validator also checks requested application type, flow pattern, and structure when those are meaningful for the CWE.

## Analyzer Validation

Bandit and Semgrep are optional unless `--require-tools` is set. With `--require-tools`, missing or failing tools reject the candidate.

Semgrep uses the SynVulCommit rules under `synvulcommit/rules/`. The validation policy requires the expected target-CWE finding before the fix and rejects any configured SynVulCommit CWE rule that remains in the fixed code, including rules from a different CWE.

This cross-CWE post-fix policy exists because generated samples sometimes accidentally retained unrelated vulnerabilities, such as SQL construction inside non-SQL samples.

## Reviewer Gate

Review is enabled by default. After deterministic validation passes, a blinded second-stage reviewer sees:

- requested CWE and context,
- vulnerable code,
- fixed code.

The reviewer must return strict JSON:

```json
{
  "verdict": "pass",
  "cwe_correct": true,
  "fix_correct": true,
  "context_correct": true,
  "runtime_plausible": true,
  "reason_category": "none"
}
```

Any `fail`, `unsure`, malformed JSON, inconsistent fields, or reviewer-provider error rejects the attempt. Reviewer prompts and raw responses are not exported to VUDENC files or metadata sidecars.

By default, the reviewer reuses the generation provider. `--review-provider` can override this with `mock`, `openai_compatible`, or `local_http`, using the `SYNVUL_REVIEW_*` environment variables.

`--no-review` is for diagnostics only. It should not be used for production training data.

## Duplicate Rejection

`DiversityIndex` indexes the vulnerable/fixed pair, not only the vulnerable file. Rejection order is:

1. exact normalized code-pair hash,
2. exact normalized-AST pair fingerprint,
3. same-CWE token-shingle near duplicate at Jaccard similarity `>= 0.90`.

The shingle index uses normalized token 5-grams over vulnerable code, a fixed-code separator, and fixed code. Identifiers and literals are normalized while Python keywords and operators are preserved.

Duplicate diagnostics are stored in rejected records using safe structured fields: check type, matched sample id/CWE/mode, threshold, and similarity score when relevant.

## Failure Behavior

If any planned quota slot remains unfilled after `--max-attempts`, generation writes all accepted records and audit files but exits with status `1`. This is intentional. It prevents a partial dataset from looking like a complete target run.

The most useful files after a run are:

```text
samples.jsonl
rejected.jsonl
diversity_summary.json
dataset_verification.json
vudenc/
```

Use `rejected.jsonl` to identify whether failures are mostly provider quality, structural mismatch, analyzer findings, review failures, or duplicate rejection.
