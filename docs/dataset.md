# Dataset Format And Verification

This document describes the internal dataset logs, the clean VUDENC export, and the verifier.

## Internal Logs

Generation writes internal audit logs to the selected output directory:

```text
samples.jsonl
rejected.jsonl
diversity_summary.json
dataset_verification.json
vudenc/
```

`samples.jsonl` contains accepted records. These records preserve detailed generation, context, validation, review, and provenance fields. They are useful for auditing and rebuilding exports, but they are not the final model-input format.

`rejected.jsonl` contains failed attempts. It is intentionally more detailed than training exports so failures can be diagnosed. It should not be used as training input.

`diversity_summary.json` reports quota coverage and unfilled slots.

`dataset_verification.json` is an aggregate audit report. It is not training input.

## Clean VUDENC Export

The model-facing export is `vudenc/plain_<mode>`.

Each `plain_<mode>` file is a strict VUDENC-style commit structure. It contains only:

- `msg`,
- `files[filename].source`,
- `sourceWithComments`,
- `sourcecodeafter`,
- `changes` with:
  - unified diff,
  - add/remove counts,
  - relative filename,
  - `badparts`,
  - `goodparts`.

The export intentionally excludes:

- local filesystem paths,
- commands,
- raw validation objects,
- raw reviewer objects,
- provider payloads,
- endpoint URLs,
- credentials or authorization data,
- temporary directories,
- tracebacks.

The training contract is that downstream VUDENC-style models consume vulnerable source and changed vulnerable fragments, especially `files[].source` and `changes[].badparts`.

## Metadata Sidecar

Every export also writes:

```text
vudenc/metadata.jsonl
```

This file has one sanitized row per exported accepted sample. It links the internal record to the exported plain file without copying source code or raw tool payloads.

Allowed sidecar fields include:

- sample id,
- CWE and mode,
- plain export filename,
- row index,
- repository and commit id aliases used in the export,
- filename,
- generation context,
- provider/model when present,
- prompt hash,
- seed,
- attempt,
- generation timestamp,
- validation pass state and safe summaries,
- Bandit/Semgrep statuses and safe rule ids,
- reviewer verdict summary.

The sidecar excludes commands, absolute paths, temporary directories, return payloads, tracebacks, raw findings, endpoint URLs, authorization values, API keys, and source code.

`metadata.jsonl` is for audit and provenance only. It should be excluded from model-training pipelines.

## Dataset Verification

Run the verifier against an accepted JSONL:

```powershell
.\.venv\Scripts\python -m synvulcommit.verify_dataset --input output_pilot\samples.jsonl
```

Defaults are derived from the input path:

- rejected log: `rejected.jsonl`,
- VUDENC export directory: `vudenc/`,
- report path: `dataset_verification.json`.

The verifier exits `0` for a clean dataset and `1` for verification errors.

It reports:

- accepted and rejected counts by CWE and mode,
- counts by context dimension,
- full context tuple counts,
- duplicate rates in policy order,
- validation pass/fail/missing/warning summaries,
- structural status,
- Bandit and Semgrep before/after status distributions,
- reviewer pass/fail/legacy counts,
- rejection breakdowns by safe category,
- export integrity results.

Validation warnings are counted but are not fatal.

## Fatal Verification Errors

Verification fails for:

- missing validation on accepted records,
- failed validation on accepted records,
- reviewer-required accepted records without a complete pass,
- duplicate accepted records under the active diversity policy,
- post-fix SynVulCommit Semgrep findings,
- unknown modes,
- duplicate sample ids,
- orphaned commits,
- missing or duplicate metadata rows,
- malformed `plain_<mode>` schema,
- extra forbidden export fields,
- exported source/diff/badparts/goodparts mismatch.

The report contains aggregate counts and safe identifiers only. It does not copy generated source code or raw analyzer/provider payloads.

## Revalidation And Rebuilds

When validation rules are strengthened, existing generated outputs should not be edited manually. Rebuild into a new output directory:

```powershell
.\.venv\Scripts\python -m synvulcommit.revalidate_dataset `
  --input output_old `
  --output output_revalidated `
  --require-tools `
  --workers 16
```

Passing records keep their code, context, provenance, and existing reviewer result, but receive the new validation result. Failing records are quarantined into the new `rejected.jsonl` with a `revalidation` marker.

The command writes:

```text
revalidation_summary.json
samples.jsonl
rejected.jsonl
vudenc/
dataset_verification.json
```

The source output directory remains unchanged.

After revalidation, resume generation into the rebuilt directory to fill deficits:

```powershell
.\.venv\Scripts\python -m synvulcommit.run_generation `
  --output output_revalidated `
  --provider openai_compatible `
  --require-tools `
  --workers 16 `
  --max-attempts 8 `
  --per-cwe 100
```

Sample ids continue after the highest retained numeric suffix, so retained records with gaps do not collide with newly generated records.
