# Generation Pipeline

This document describes the current `synvulcommit.run_generation` workflow. The implementation is resumable, quota-driven, concurrent, and deliberately fails closed when strict validation or final dataset verification does not pass.

## Command And Defaults

Run from the repository root:

```powershell
.\.venv\Scripts\python -m synvulcommit.run_generation [options]
```

Important defaults:

| Option | Default | Meaning |
| --- | ---: | --- |
| `--per-cwe` | `1` | Target accepted records per selected CWE, including resumable existing records of the selected profile. |
| `--provider` | `mock` | `mock`, `openai_compatible`, or `local_http`. |
| `--output` | `output` | Internal logs and exports directory. |
| `--seed` | `1337` | Deterministic quota-planning seed. |
| `--max-attempts` | `5` | Attempts for each planned context slot. |
| `--generation-profile` | `compact` | `compact` or `window_balanced`. |
| `--workers` | `10` | Maximum concurrent slot pipelines. |
| reviewer | enabled | Reuses the generation provider unless `--review-provider` is set. |
| analyzer strictness | non-strict | Add `--require-tools` for production data. |
| export | enabled | Add `--no-export` to skip VUDENC export and final verification. |

Repeat `--cwe` to select modes, keys, or CWE identifiers, for example `--cwe sql --cwe CWE-79`. With no filter, all seven modes are planned.

## Pipeline Stages

Each planned slot follows this order:

1. Build a deterministic `GenerationSpec` containing CWE, application type, flow pattern, structure, difficulty, sample index, and profile.
2. Build a strict JSON-only prompt and call the configured provider.
3. Normalize the response into one Python before/after pair.
4. Build the unified diff locally and derive `badparts` and `goodparts`.
5. Run syntax, known-framework-import, requested-context, CWE-specific structural, and profile checks.
6. Scan the vulnerable and fixed files with Bandit and the repository Semgrep rules.
7. Run the blinded reviewer when review is enabled.
8. Reject exact, normalized-AST, and near-duplicate code pairs.
9. Append the accepted record to `samples.jsonl`, or append diagnostic data to `rejected.jsonl`.

After all slots finish, the run writes `diversity_summary.json`. Unless `--no-export` is set, it then rebuilds `vudenc/`, writes `dataset_verification.json`, and fails if verification reports any error.

The generator is append-oriented for internal JSONL logs. It does not edit previously accepted records during a normal resumed run.

## Supported Modes And Contexts

| Mode | CWE | Planned application types |
| --- | --- | --- |
| `sql` | CWE-89 SQL injection | Flask, Django, API, script |
| `command_injection` | CWE-78 OS command injection | Flask, Django, CLI, API, script |
| `directory_traversal` | CWE-22 path traversal | Flask, API, CLI, script |
| `open_redirect` | CWE-601 open redirect | Flask, Django, API |
| `remote_code_execution` | CWE-94 remote code execution | Flask, Django, CLI, API, script |
| `xss` | CWE-79 cross-site scripting | Flask, Django, API |
| `xsrf` | CWE-352 cross-site request forgery | Flask only |

The remaining context dimensions are:

- flow: `direct`, `indirect`, or `complex`;
- difficulty: `easy`, `medium`, or `hard`;
- structure: `single_function`, `class_based`, or `multi_function`.

Not every combination is valid. `single_function` only supports direct flow; `multi_function` supports indirect and complex flow; `class_based` supports all three. The `window_balanced` profile excludes `single_function` entirely.

## Deterministic Quota Planning And Resume

For each CWE, compatible context tuples are scored in this exact order:

1. full tuple count;
2. application-type marginal count;
3. flow-pattern marginal count;
4. structure marginal count;
5. difficulty marginal count;
6. structure/flow flexibility, preferring the less flexible structure when counts tie;
7. a stable SHA-256 tie-break based on seed, CWE, slot, and tuple.

Existing accepted records count only when their CWE/mode and generation profile match the current plan. Legacy records without a profile are treated as `compact`. Existing context counts steer later slots toward underrepresented tuples.

Rejected candidates retry the same `GenerationSpec`; rejection does not randomize or replace its planned context. `diversity_summary.json` records existing, planned, accepted, rejected-attempt, and unfilled counts together with marginal and full-tuple coverage.

`--per-cwe` is a target, not an increment. If an output already contains the target number for a selected CWE/profile, the provider is not called for that CWE.

## Generation Profiles

### `compact`

This is the default and the profile of the reported corpus. Its prompt requests self-contained files under 55 lines and 2,800 characters. Those two size limits are prompt requirements rather than separate validator thresholds.

### `window_balanced`

This profile adds enforced validation intended for 200-token VUDENC-style windowing:

- vulnerable source must contain 420-900 code tokens;
- `badparts` must cover no more than 15% of vulnerable tokens;
- vulnerable source must yield at least one positive and one negative 200-token window using stride 5;
- fixed source must retain at least 75% of the vulnerable token count;
- `single_function` slots are excluded.

The prompt additionally asks for meaningful clean context before and after a localized security change. The profile is stored in the internal record and sanitized metadata sidecar; it does not alter the clean `plain_<mode>` schema.

## Provider Response Contract

The generation provider is asked for exactly one JSON object:

```json
{
  "commit_message": "short Git-style security fix message",
  "filename": "relative/path.py",
  "vulnerable_code": "complete vulnerable Python file",
  "fixed_code": "complete fixed Python file",
  "vulnerable_lines": ["exact source line"],
  "fixed_lines": ["exact source line"]
}
```

`commit_message`, `vulnerable_code`, and `fixed_code` are required. A missing filename becomes `app.py`; a filename without `.py` receives that suffix. Newlines are normalized and a trailing newline is added.

The generator ignores any provider-supplied diff and builds its own. Exact explicit vulnerable/fixed lines are used only when every listed line is present in the corresponding source. Otherwise changed diff lines are used. CWE-specific inference is a final fallback when a side has no changed parts. A candidate still fails validation if its final `badparts` or `goodparts` list is empty.

Raw provider responses are kept only in memory and are not written to accepted records or clean exports.

## Provider Configuration

The code reads environment variables directly; it does not automatically load a `.env` file.

### OpenAI-compatible HTTP

`SYNVUL_API_KEY` and `SYNVUL_MODEL` are required. Other generation settings are:

| Variable | Default |
| --- | --- |
| `SYNVUL_BASE_URL` | `https://api.openai.com/v1` |
| `SYNVUL_TEMPERATURE` | `0.2` |
| `SYNVUL_MAX_TOKENS` | `1800` |
| `SYNVUL_REQUEST_TIMEOUT` | `180` seconds |
| `SYNVUL_RESPONSE_FORMAT` | unset; `json_object` is automatically used for DeepSeek URLs |
| `SYNVUL_THINKING_MODE` | unset; accepts `enabled` or `disabled` |

The request URL is `<base URL>/chat/completions`. For DeepSeek, for example:

```powershell
$env:SYNVUL_BASE_URL="https://api.deepseek.com"
$env:SYNVUL_API_KEY="your_api_key"
$env:SYNVUL_MODEL="deepseek-chat"
```

### Local HTTP

`SYNVUL_LOCAL_URL` is required. Supported settings are:

| Variable | Default/behavior |
| --- | --- |
| `SYNVUL_LOCAL_MODEL` | Optional model name in the request body. |
| `SYNVUL_LOCAL_AUTH` | Optional complete `Authorization` header value. |
| `SYNVUL_LOCAL_FORMAT` | `json` |
| `SYNVUL_TEMPERATURE` | `0.2` |
| `SYNVUL_NUM_PREDICT` | `4096` |
| `SYNVUL_REQUEST_TIMEOUT` | `180` seconds |

The local request includes both a combined `prompt` and chat-style `messages` to support common Ollama-compatible response shapes.

### Separate Reviewer Configuration

Without `--review-provider`, review uses the generation provider and its normal `SYNVUL_*` settings. Supplying `--review-provider` switches that provider to the equivalent `SYNVUL_REVIEW_*` namespace, such as `SYNVUL_REVIEW_API_KEY`, `SYNVUL_REVIEW_MODEL`, or `SYNVUL_REVIEW_LOCAL_URL`.

`SYNVUL_REVIEW_MAX_TOKENS` controls reviewer output in both cases; its default is `512` and its accepted range is 128-8192.

## Deterministic Validation

Both files must parse as Python. For a small allowlist of known Flask, Flask-WTF, WTForms, Django, and MarkupSafe modules, imported symbol names are also checked to catch invented APIs.

The validator checks the requested application type, structure, and flow when applicable, then enforces mode-specific evidence:

- SQL: dynamic vulnerable query execution; fixed static query text with appropriate placeholders and bound values; additional Django serialization checks.
- Command injection: vulnerable shell execution; fixed argument-list subprocess use without `shell=True` or `os.system`.
- Path traversal: unchecked user path before; path-aware containment after. String-prefix checks are not accepted.
- Open redirect: unchecked redirect before; parsed/local or allowlisted target after.
- RCE: `eval`, `exec`, or equivalent before; no dynamic execution and a literal parser or fixed dispatch strategy after.
- XSS: unescaped HTML flow before; escaping or safe template binding after.
- XSRF: missing/disabled protection before; correctly initialized CSRF protection after.

These checks establish recognizable dataset patterns; they are not a general proof of application security.

## Bandit And Semgrep Policy

The vulnerable and fixed files are scanned together per tool and findings are split back by path.

When tools run successfully:

- a missing expected Bandit finding before the fix is a warning;
- an expected Bandit finding remaining after the fix is fatal;
- the expected target-CWE Semgrep finding must appear before the fix;
- no target-CWE or cross-CWE SynVulCommit Semgrep finding may remain after the fix.

There is one narrow XSS exception: an `xss-helper` finding may remain as a warning when structural validation confirms that escaping is correct.

If a tool is missing, times out, emits invalid output, or exits unexpectedly, the candidate receives a warning by default. With `--require-tools`, the same condition is fatal. Production generation should use `--require-tools`.

## Reviewer Gate

Review runs only after deterministic validation passes. The reviewer sees the expected CWE/context and both source versions, but not generator identity, endpoint, prompt metadata, or previous validation output.

It must return exactly these fields:

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

Allowed verdicts are `pass`, `fail`, and `unsure`; allowed reason categories are `none`, `wrong_cwe`, `incomplete_fix`, `wrong_context`, `runtime_issue`, and `other`. A pass is valid only when all booleans are true and the category is `none`. Any schema error, inconsistency, non-pass verdict, or provider error rejects the attempt.

Accepted records store only the parsed assessment plus reviewer provider/model when available. Reviewer prompts and raw responses are not persisted. `--no-review` writes an explicit skipped review state and is intended only for diagnostics.

## Duplicate Policy

Duplicate checks index the combined vulnerable/fixed pair in this order:

1. exact SHA-256 of newline-normalized source pairs, across all CWEs;
2. exact fingerprint of both ASTs after normalizing names and literals, across all CWEs;
3. same-CWE Jaccard similarity of normalized token 5-grams, rejected at `>= 0.90`.

Rejected duplicate records include the safe check name and matched sample/CWE/mode, plus threshold and similarity for near duplicates.

## Concurrency, Exit Status, And Outputs

Each planned slot runs in a thread up to `min(--workers, planned slots)`. File appends, sample-id allocation, duplicate indexing, and coverage counters are protected by a shared lock. Accepted IDs use the next numeric suffix after retained accepted records; rejected attempts can reuse a prospective ID because only accepted records advance the sequence.

Exit behavior:

- `0`: every selected target is met and, when enabled, final export verification passes;
- `1`: at least one quota remains unfilled or final verification fails;
- `2`: provider preflight or command-line configuration error.

A normal exported run produces:

```text
<output>/
  samples.jsonl
  rejected.jsonl
  diversity_summary.json
  dataset_verification.json
  vudenc/
    metadata.jsonl
    plain_<mode>
```

With `--no-export`, `vudenc/` and `dataset_verification.json` are not rebuilt. See [Dataset Format And Verification](dataset.md) for the record and export contracts.
