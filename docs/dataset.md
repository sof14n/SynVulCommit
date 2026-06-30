# Dataset Format And Verification

SynVulCommit keeps rich internal JSONL records for audit and recovery, then derives a smaller VUDENC-compatible export for model input. The internal logs, metadata sidecar, and verifier report are not training data.

## Output Directory Contract

A normal generation run with export enabled writes:

```text
<output>/
  samples.jsonl
  rejected.jsonl
  diversity_summary.json
  dataset_verification.json
  vudenc/
    metadata.jsonl
    plain_sql
    plain_command_injection
    plain_directory_traversal
    plain_open_redirect
    plain_remote_code_execution
    plain_xss
    plain_xsrf
```

`samples.jsonl` and `rejected.jsonl` are created before generation begins and are append-only during a normal run. `diversity_summary.json` is rewritten at the end of each run. `vudenc/` and `dataset_verification.json` are rebuilt unless `--no-export` is supplied.

## Accepted Record Schema

Every line of `samples.jsonl` is one accepted JSON object with these fields:

| Field | Content |
| --- | --- |
| `id` | Accepted sample ID such as `CWE-89_sql_000001`. |
| `cwe`, `cwe_name`, `mode` | Canonical vulnerability identity. |
| `context` | Full generation specification: CWE fields, application type, flow, difficulty, structure, sample index, and generation profile. |
| `generation_profile` | Top-level `compact` or `window_balanced` copy for compatibility. |
| `attempt` | Attempt number within that planned slot. |
| `commit_message`, `filename` | Commit-like description and relative Python filename. |
| `vulnerable_code`, `fixed_code` | Complete normalized source versions. |
| `diff` | Locally generated unified diff. |
| `badparts`, `goodparts` | Exact vulnerable/fixed fragments used by VUDENC labeling. |
| `provider` | Generation provider type. |
| `validation` | Structural, analyzer, warning/reason, and optional window-balance evidence. |
| `review` | Required/completed/skipped state and parsed reviewer assessment. |

The current generation path does not persist raw provider responses, generation prompts, reviewer prompts, reviewer raw responses, API endpoints, or credentials.

`validation` contains `passed`, `reasons`, `warnings`, `structural`, and separate `bandit_before`, `bandit_after`, `semgrep_before`, and `semgrep_after` objects. `window_balanced` records also contain `window_balance`.

## Rejected Record Variants

`rejected.jsonl` is intentionally heterogeneous because failure can happen at different stages:

- provider failures contain context, profile, attempt, provider, review-not-run state, and a safe rejection reason, but no generated source;
- structural/analyzer failures contain the full candidate and validation object;
- reviewer failures contain the full candidate, passing deterministic validation, parsed/error review state, and rejection reason;
- diversity failures contain the full candidate plus `diversity_rejection` diagnostics.

Rejected candidate IDs are prospective and are not guaranteed to be unique. Only accepted records advance the persistent sample-ID sequence. Rejected data is diagnostic and must not be used as positive training input.

## Diversity Summary

`diversity_summary.json` combines:

- total indexed accepted records and context distributions;
- duplicate-rejection counts and policy parameters;
- per-CWE quota coverage, including existing, planned, accepted, rejected attempts, and unfilled slots;
- marginal and full-tuple context counts and uncovered values;
- worker throughput and provider/validation/reviewer work time;
- reviewer pass/rejection/error counts for the run.

The timing values are operational measurements, not deterministic dataset properties.

## Clean VUDENC Export

Each extensionless `vudenc/plain_<mode>` file is JSON with the VUDENC-style nesting:

```text
repository alias
  -> commit id
     -> msg
     -> files
        -> relative filename
           -> source
           -> sourceWithComments
           -> sourcecodeafter
           -> changes[]
```

Each change object contains exactly:

- `diff`;
- `add`, the number of exported `goodparts`;
- `remove`, the number of exported `badparts`;
- `filename`;
- `badparts`;
- `goodparts`.

The exporter creates repository aliases as `synvulcommit/<mode>` and normally uses the internal sample ID as the commit ID. It writes all seven `plain_<mode>` files even when a mode has no records.

The training contract uses vulnerable source and changed vulnerable fragments, especially `files[filename].source`/`sourceWithComments` and `changes[].badparts`. `sourcecodeafter` and `goodparts` preserve the paired fix for repair-oriented uses.

## Export Sanitization

The clean files intentionally exclude internal context, validation, analyzer commands, raw findings, review objects, provider payloads, local paths, tracebacks, endpoints, and credentials.

Before export:

- filenames are converted to safe relative paths;
- unsafe commit messages are replaced with `Synthetic security fix`;
- a diff containing unsafe path-like metadata is regenerated from source and the sanitized filename;
- missing changed parts are re-derived from the diff.

This is a narrow export allowlist, not a general secret scanner for generated source. Generated source itself is model data and is therefore preserved.

## Metadata Sidecar

`vudenc/metadata.jsonl` contains one sanitized row per accepted record, in the same per-mode export order. It links audit records to clean commits without copying source code.

Every row contains:

- `id`, `cwe`, `cwe_name`, and `mode`;
- `plain_file`, `row_index`, `repo`, `commit_id`, and `filename`;
- `generation_profile`;
- allowlisted `context`;
- allowlisted `provenance`;
- `validation_summary`;
- optional `review_summary`.

Allowlisted context fields are CWE identity, mode, application type, flow, difficulty, structure, and sample index. Allowlisted provenance keys are `provider`, `model`, `prompt_sha256`, `seed`, `attempt`, and `generated_at` when present. Current generator records normally provide `provider` and `attempt`; the remaining keys support compatible imported/legacy records.

The validation summary contains only pass state, reason/warning counts, structural markers, safe tool statuses/finding IDs, and optional numeric window-balance measurements. The review summary contains required/status/verdict/category/provider/model and boolean assessments when available.

The sidecar excludes source, diffs, commands, raw findings, raw payloads, absolute paths, URLs, authorization values, API keys, and tracebacks. It is audit metadata and must be excluded from model training.

## Export Command

Rebuild exports from accepted records:

```powershell
.\.venv\Scripts\python -m synvulcommit.export_vudenc `
  --input output\samples.jsonl `
  --out output\vudenc
```

CLI defaults are `output/samples.jsonl` and `output/vudenc`. Existing expected files are overwritten. The command does not validate candidates again; run the verifier afterward when exporting manually.

## Dataset Verifier

Run:

```powershell
.\.venv\Scripts\python -m synvulcommit.verify_dataset `
  --input output\samples.jsonl
```

Paths default relative to the accepted JSONL:

| Input | Default |
| --- | --- |
| rejected log | sibling `rejected.jsonl` |
| VUDENC directory | sibling `vudenc/` |
| report | sibling `dataset_verification.json` |

Override them with `--rejected`, `--vudenc`, and `--out`. The verifier writes a schema-versioned aggregate JSON report and exits `0` only when its status is `pass`; verification errors return `1`.

### Report Sections

The report contains:

- accepted totals and per-CWE context/full-tuple coverage;
- policy-ordered duplicate counts and rates;
- accepted validation pass/fail/missing and warning counts;
- structural status and Bandit/Semgrep before/after status distributions;
- post-fix SynVulCommit Semgrep rule IDs;
- accepted and rejected reviewer summaries;
- rejected counts by mode, safe category, context, and diversity check;
- expected/actual export counts and integrity errors;
- a final safe error list containing codes and, where safe, sample IDs/modes.

Warnings stored on otherwise passing validation records are counted but are not fatal by themselves.

### Fatal Conditions

Verification fails for any of the following:

- missing/unreadable accepted or rejected JSONL;
- accepted records with missing or failed validation;
- missing or failed structural validation;
- a `window_balanced` record without window-balance validation data;
- reviewer-required accepted records without a complete passing assessment;
- duplicates under the current exact/AST/near-duplicate policy;
- any disallowed post-fix SynVulCommit Semgrep finding;
- duplicate accepted IDs or unknown modes;
- missing, extra, invalid, or mismatched `plain_<mode>` files;
- missing, invalid, duplicate/mismatched, or broken metadata links;
- any exported source, diff, filename, badpart, goodpart, message, or schema difference from a clean rebuild of the accepted records.

Integrity is checked by rebuilding the expected plain payloads and metadata in memory and comparing them with disk. This catches both missing data and extra/forbidden fields.

The report deliberately stores aggregate counts and safe issue identifiers rather than copying generated code or unsafe diagnostic strings.

## Revalidation And Quarantine

When rules change, rebuild an older accepted corpus into a different empty directory:

```powershell
.\.venv\Scripts\python -m synvulcommit.revalidate_dataset `
  --input output_old `
  --output output_revalidated `
  --require-tools `
  --workers 10
```

The command requires `--input/samples.jsonl`, refuses to use the same source and destination, and refuses a non-empty destination. It reconstructs each generation specification and candidate from the accepted record, then reruns current deterministic/analyzer validation concurrently.

Passing records retain their ID, code, context, generation fields, and previous reviewer result, but receive the new validation object. Failures move to the new `rejected.jsonl` with a `revalidation` block containing the source ID, quarantine status, and safe reason categories.

The rebuilt directory contains:

```text
samples.jsonl
rejected.jsonl
revalidation_summary.json
dataset_verification.json
vudenc/
```

Revalidation always rebuilds exports and runs verification. Its CLI exits `0` only when the rebuilt verification passes; invalid arguments or a failed rebuilt verification return nonzero. The source directory is never modified.

Afterward, normal generation can resume into the rebuilt directory. New accepted IDs continue after the highest retained numeric suffix, so quarantined gaps do not collide with new records.
