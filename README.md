# Lab 5: SynVulCommit

SynVulCommit is a standalone synthetic vulnerability-commit generator. It asks an AI provider to generate paired vulnerable/fixed Python code, applies deterministic validation, requires a blinded second-stage LLM review, stores accepted samples as JSONL, and exports them to the VUDENC-style `plain_<mode>` files used by the older project code.

## Quick start

Run these commands from this folder:

```powershell
cd "C:\Users\Lenovo\VulnerabilityDetection\Code\lab 5"
.\.venv\Scripts\python -m synvulcommit.run_generation --per-cwe 1 --provider mock --require-tools
```

Outputs:

```text
output/samples.jsonl
output/rejected.jsonl
output/dataset_verification.json
output/vudenc/metadata.jsonl
output/vudenc/plain_sql
output/vudenc/plain_command_injection
output/vudenc/plain_directory_traversal
output/vudenc/plain_open_redirect
output/vudenc/plain_remote_code_execution
output/vudenc/plain_xss
output/vudenc/plain_xsrf
```

The `plain_<mode>` files contain only the VUDENC commit/file structure used by the downstream model: vulnerable source and changed vulnerable fragments. `metadata.jsonl` is a separate sanitized audit sidecar that links every exported sample to its CWE, generation context, provenance, validation summary, and reviewer verdict summary. Neither file includes commands, local paths, raw analyzer or reviewer output, endpoint URLs, or API credentials. Do not use `metadata.jsonl` as model-training input.

## Reviewer gate

Review is enabled by default for all new generation attempts. After deterministic validation passes, a blinded reviewer receives only the requested CWE/context plus the vulnerable and fixed code. The reviewer must return strict JSON with a `pass` verdict, correct CWE/fix/context/runtime assessments, and reason category `none`; `fail`, `unsure`, malformed JSON, inconsistent fields, and reviewer-provider errors reject the attempt and retry the same planned quota slot. This is a hard quality gate, so it lowers yield and adds one LLM call per statically valid candidate.

By default, review reuses the generation provider and its configuration. Use `--review-provider` to independently select `mock`, `openai_compatible`, or `local_http`; the override reads the `SYNVUL_REVIEW_*` profile. `--no-review` is for diagnostic runs only and records a sanitized `skipped` review state. It must not be used for the production training dataset.

```powershell
# Use the same provider/model for generation and review (default).
.\.venv\Scripts\python -m synvulcommit.run_generation --per-cwe 10 --provider openai_compatible --require-tools

# Use an independent OpenAI-compatible reviewer.
$env:SYNVUL_REVIEW_BASE_URL="https://api.example.com/v1"
$env:SYNVUL_REVIEW_API_KEY="your_reviewer_key"
$env:SYNVUL_REVIEW_MODEL="reviewer-model"
.\.venv\Scripts\python -m synvulcommit.run_generation --per-cwe 10 --provider openai_compatible --review-provider openai_compatible --require-tools

# Use an Ollama/local HTTP reviewer.
$env:SYNVUL_REVIEW_LOCAL_URL="http://127.0.0.1:11434/api/generate"
$env:SYNVUL_REVIEW_LOCAL_MODEL="qwen-review"
.\.venv\Scripts\python -m synvulcommit.run_generation --per-cwe 10 --provider openai_compatible --review-provider local_http --require-tools
```

When `--review-provider` selects an independent profile, optional settings are `SYNVUL_REVIEW_TEMPERATURE` and `SYNVUL_REVIEW_REQUEST_TIMEOUT`; local reviewers also support `SYNVUL_REVIEW_LOCAL_AUTH` and `SYNVUL_REVIEW_LOCAL_FORMAT`. Without an override, the reviewer reuses the corresponding `SYNVUL_*` settings. `SYNVUL_REVIEW_MAX_TOKENS` applies in both cases and defaults to `512` (range `128`-`8192`). Reviewer prompts and raw responses are never written to JSONL exports or the VUDENC sidecar. Existing records are not backfilled; the verifier reports them as legacy records without review.

Live reviewer integration tests are opt-in and read credentials only from the environment:

```powershell
# Uses the configured SYNVUL_* OpenAI-compatible provider, such as DeepSeek.
$env:SYNVUL_RUN_LIVE_REVIEW_TESTS="1"
.\.venv\Scripts\python -m unittest discover -s tests -p test_reviewer_integration.py -v

# Uses the independent SYNVUL_REVIEW_LOCAL_* local/ollama profile.
$env:SYNVUL_RUN_LIVE_LOCAL_REVIEW_TESTS="1"
.\.venv\Scripts\python -m unittest discover -s tests -p test_reviewer_integration.py -v
```

## Diversity And Coverage

Generation uses deterministic quota planning across application type, data-flow pattern, difficulty, and program structure. It plans only compatible flow/structure pairs: `single_function` uses `direct`, `multi_function` uses `indirect` or `complex`, and `class_based` supports all three flow patterns. `--per-cwe` is a target accepted count, not a number of attempts or new samples. Existing accepted records in the selected output directory count toward that target, so rerunning a partial job plans only the remaining deficit and does not call the provider for CWEs already at target. Existing records also steer later slots toward underrepresented contexts. The generator rejects exact vulnerable/fixed code-pair duplicates, normalized-AST duplicates, and same-CWE token-shingle near duplicates at a Jaccard similarity threshold of `0.90`.

For SQL generation, the prompt and structural checks also enforce the requested application type, structure, and flow pattern. Fixed SQL must use a static query with placeholders and bound values; a static query variable passed to `execute(query, params)` is accepted, while dynamic query construction remains rejected.

Complex flow prompts are CWE-specific. Only SQL samples use a `build_query` to `execute_query` data flow; other CWE samples use a generic source-to-intermediate-to-requested-sink flow and explicitly prohibit unrelated SQL/database behavior. The deterministic validator still rejects any configured SynVulCommit CWE rule left in, or introduced by, the fixed code.

Every run writes `diversity_summary.json` with each CWE's target, existing accepted count, newly accepted count, total accepted count, planned/rejected/unfilled slots, marginal distributions, and uncovered context tuples. If any target remains unmet after `--max-attempts`, generation still exports accepted records but exits with status `1`.

Normal exports also write `dataset_verification.json`. The verifier reports accepted/rejected counts by CWE and context, policy-ordered duplicate rates, validation and tool-status summaries, reviewer pass/fail/legacy counts, rejection categories, and strict VUDENC export integrity. Missing or failed accepted-record validation, a reviewer-required accepted record without a complete pass, accepted duplicates, or an export mismatch make generation exit with status `1`; validation warnings are reported but remain non-fatal. The report is audit-only and must not be used as model-training input.

Run the verifier separately against an existing output directory:

```powershell
.\.venv\Scripts\python -m synvulcommit.verify_dataset --input output/samples.jsonl
```

By default it reads `rejected.jsonl` and `vudenc/` beside the input and writes `dataset_verification.json` beside the input. It exits with status `1` when strict verification finds errors.

## Rebuild A Strict Dataset

When validation rules are strengthened, do not edit existing JSONL or `plain_<mode>` files. Revalidate accepted records into a new empty output directory, which retains only records that pass the current checks and quarantines the rest in its internal `rejected.jsonl`:

```powershell
.\.venv\Scripts\python -m synvulcommit.revalidate_dataset `
  --input output_sql_review_v1 `
  --output output_scale_v2 `
  --require-tools `
  --workers 16
```

The source output remains unchanged. The new output contains `revalidation_summary.json`, fresh VUDENC exports, and strict verification. Resume generation against the rebuilt directory to fill only the remaining per-CWE quota; IDs continue after the highest retained suffix, even when invalid records created gaps.

The strict policy rejects a fixed sample when Semgrep reports any configured SynVulCommit CWE rule after the fix, including a rule for a CWE other than the sample label. Directory-traversal fixes must use path-aware containment and cannot use `startswith` for path-prefix checks.

The mock provider is deterministic and works without an API key. It is meant for smoke-testing the pipeline.

## Optional validation tools

The pipeline always runs CWE-specific structural checks. If Bandit or Semgrep are installed, it also runs them and records their findings.

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -m semgrep.console_scripts.pysemgrep --version
```

Use the same `.venv` Python interpreter to run generation. This avoids conflicts with unrelated globally installed OpenTelemetry packages.

Use strict external-tool validation when you want missing Bandit/Semgrep to fail generation:

```powershell
python -m synvulcommit.run_generation --per-cwe 1 --provider mock --require-tools
```

## OpenAI-compatible provider

Any chat-completions-compatible endpoint can be used:

```powershell
$env:SYNVUL_BASE_URL="https://api.openai.com/v1"
$env:SYNVUL_API_KEY="your_api_key"
$env:SYNVUL_MODEL="gpt-4.1-mini"
.\.venv\Scripts\python -m synvulcommit.run_generation --per-cwe 10 --provider openai_compatible --require-tools
```

For DeepSeek, set `SYNVUL_BASE_URL` to `https://api.deepseek.com` and `SYNVUL_MODEL` to your enabled DeepSeek chat model. Provide `SYNVUL_API_KEY` through the environment; do not place it in source files or output directories. DeepSeek requests automatically use JSON-object mode and a temperature of `0.2`; override either with `SYNVUL_RESPONSE_FORMAT` or `SYNVUL_TEMPERATURE`.

Generation runs up to 10 generation, validation, and review pipelines concurrently by default. Each pipeline scans its vulnerable/fixed pair once with Bandit and once with Semgrep, then splits the findings by file before invoking the reviewer; it does not skip analyzer coverage. Set `--workers 1` to preserve serial execution, or lower `--workers` if either provider returns rate-limit errors. The runner prints wall-time throughput and writes the same safe aggregate measurements to `diversity_summary.json`.

OpenAI-compatible requests cap completions at 1,800 tokens by default to avoid slow, overlong responses. Set `SYNVUL_MAX_TOKENS` from `256` to `8192` to adjust that limit. Provider requests allow 180 seconds by default. Set `SYNVUL_REQUEST_TIMEOUT` to a value from `1` to `600` seconds when a provider needs a different limit. A timeout is recorded as a failed generation attempt and retried within `--max-attempts`; it no longer aborts the complete batch.

For OpenRouter or similar gateways, set `SYNVUL_BASE_URL` to the gateway's OpenAI-compatible base URL and `SYNVUL_MODEL` to the routed model name.


## Local HTTP provider

Use this when a local model exposes a simple HTTP endpoint:

```powershell
$env:SYNVUL_LOCAL_URL="http://127.0.0.1:11434/api/generate"
$env:SYNVUL_LOCAL_MODEL="codellama"
python -m synvulcommit.run_generation --per-cwe 10 --provider local_http
```

The response parser accepts common shapes such as OpenAI `choices`, Ollama-style `response`, and simple `text` or `generated_text` fields.
By default, the local provider sends `format=json`, `temperature=0.2`, and `num_predict=4096`, which works well with Ollama. Set `SYNVUL_LOCAL_FORMAT=""` if your local endpoint does not accept that field.

## Export only

```powershell
python -m synvulcommit.export_vudenc --input output/samples.jsonl --out output/vudenc
```

This command regenerates all `plain_<mode>` files and `metadata.jsonl` from the accepted records.

## Notes

- This is teacher-generated synthetic supervision, not classic logit-based knowledge distillation.
- The AI generates candidates; the pipeline validates and stores only accepted samples.
- Existing project files outside `lab 5` are not modified.

## Controlled A/B/C Evaluation

The experiment package freezes a balanced synthetic subset before any model is
trained. The current verified corpus supplies `91` synthetic commit pairs for
each of the seven modes (`637` pairs total). It also loads the original VUDENC
`plain_*` files from the parent project, maps legacy `path_disclosure` to
`directory_traversal`, and caps real commits at `min(91, available)` per mode.

Preparation splits commits before source windows are produced. Therefore all
windows from a real multi-file commit remain in exactly one split. Every window
manifest includes its source dataset, commit group, CWE mode, split, and label:
changed vulnerable regions are positive and all other source windows are
negative. To keep the full 84-run CPU experiment tractable, preparation retains
a deterministic four positive and four negative windows per file (when present).
The real VUDENC test split is frozen and reused for A, B, and C.

```powershell
# This runs in the Lab 5 generator environment and does not call an LLM.
.\.venv\Scripts\python.exe -m synvulcommit.prepare_experiment `
  --synthetic output_deepseekpro_glmreview_100_per_cwe\samples.jsonl `
  --vudenc-root ..\data `
  --out experiments\release_91_v1 `
  --per-cwe 91 `
  --seed 20260624
```

The command writes immutable selection and split manifests, `windows.jsonl`, a
dataset summary, and five diverse synthetic vulnerable/fixed pairs per CWE in
`audit/synthetic_pairs_for_manual_review.jsonl`. Review those 35 selected pairs
and record the assessment in the final report; the file deliberately marks them
as pending rather than claiming human review occurred.

Train in the Lab 3 `vudenc` Conda environment, which must contain the existing
300-dimensional Word2Vec artifact at `..\w2v\word2vec_withString10-300-200.model`.
Install `requirements-experiments.txt` there only if the environment no longer
has TensorFlow, scikit-learn, Gensim, NumPy, and Joblib.

```powershell
conda activate vudenc
python -m synvulcommit.run_experiments `
  --prepared experiments\release_91_v1 `
  --word2vec ..\w2v\word2vec_withString10-300-200.model
```

This runs LSTM, MLP, Random Forest, and 1D CNN for each CWE and condition:
`A` real VUDENC train/validation, `B` synthetic train/validation, and `C` their
training union with real validation. All runs evaluate on the same held-out real
test split. LSTM and CNN use 200-token Word2Vec sequences; MLP and Random Forest
use mean-pooled 300-dimensional vectors. The sequence cache stores Word2Vec
token IDs and loads the fixed vectors in the model, avoiding redundant
multi-gigabyte floating-point caches. Outputs include cached features, saved
models, per-run metrics, confusion matrices, `metrics.csv`, and
`comparison.md`. F1 is the primary metric; the table also reports accuracy,
precision, recall, support, and macro-F1.

Use `--smoke --epochs 1` to execute a CPU smoke run for selected models before a
full experiment. The generated verification report and the manual audit remain
required evidence in the final lab report; this synthetic comparison does not
establish real-world deployment performance.
