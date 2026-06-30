# SynVulCommit

SynVulCommit generates synthetic Python vulnerability-fixing commits and evaluates how well they transfer to real VUDENC data. Each accepted record contains vulnerable and fixed source, a commit message, a unified diff, changed vulnerable/fixed fragments, generation context, validation evidence, and reviewer provenance.

The repository has two connected workflows:

- a resumable, CWE-balanced generation pipeline with structural checks, Bandit, project-specific Semgrep rules, LLM review, duplicate rejection, clean VUDENC export, and export verification;
- a controlled A/B/C experiment pipeline that compares training on real VUDENC data, synthetic data, and their combination against the same held-out real test set.

Generated datasets, provider logs, model artifacts, experiment releases, credentials, and virtual environments are intentionally not committed. The final report snapshot recorded a 1,205-pair window-balanced corpus and selected 149 pairs per CWE (1,043 total) for evaluation, but those artifacts must be supplied locally to reproduce the experiments.

## Supported Vulnerability Modes

| Mode | CWE | Vulnerability |
| --- | --- | --- |
| `sql` | CWE-89 | SQL injection |
| `command_injection` | CWE-78 | OS command injection |
| `directory_traversal` | CWE-22 | Path traversal |
| `open_redirect` | CWE-601 | Open redirect |
| `remote_code_execution` | CWE-94 | Remote code execution |
| `xss` | CWE-79 | Cross-site scripting |
| `xsrf` | CWE-352 | Cross-site request forgery |

## How Generation Works

For every requested CWE, the planner balances compatible combinations of application type, data-flow pattern, difficulty, and program structure. Existing accepted records of the selected generation profile count toward `--per-cwe`, so an interrupted output directory can be resumed safely.

Each generated candidate passes through these gates:

1. strict provider-output parsing and diff/badpart construction;
2. Python syntax, CWE-specific structure, requested context, and optional window-balance checks;
3. Bandit and the seven project Semgrep rule sets;
4. a strict, blinded LLM reviewer, enabled by default;
5. exact code-pair, normalized-AST, and same-CWE token-shingle duplicate checks;
6. VUDENC export and a final integrity verifier.

A quota slot is retried with the same planned context after rejection. If any target remains unfilled, or the final exported dataset fails verification, generation exits with status `1` instead of presenting a partial run as complete.

## Setup And Tests

CI runs on Python 3.11. From Windows PowerShell:

```powershell
git clone https://github.com/sof14n/SynVulCommit.git
cd SynVulCommit
python -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install -r requirements.txt
```

Run the same test framework used by CI:

```powershell
.\.venv\Scripts\python -m unittest discover -s tests -v
```

The current suite discovers 112 tests. In a generator-only environment, four optional tests are expected to skip: two live reviewer calls and two NumPy/TensorFlow experiment checks. The remaining tests include real Bandit/Semgrep rule execution; running with a Python environment that has not installed `requirements.txt` will not provide an equivalent result.

CI additionally compiles the package, performs strict mock generation for all seven modes, validates the accepted counts, exports every `plain_<mode>` file, and verifies export integrity.

## End-To-End Local Smoke Test

The deterministic mock provider exercises the pipeline without an API key:

```powershell
.\.venv\Scripts\python -m synvulcommit.run_generation `
  --output output_smoke `
  --provider mock `
  --require-tools `
  --per-cwe 1
```

A successful run accepts seven records and creates:

```text
output_smoke/
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

Mock mode is a parser, validator, export, and CI fixture. It is not representative of production dataset diversity or quality.

## Production Generation

For an OpenAI-compatible chat-completions endpoint, configure the provider in the environment. For example:

```powershell
$env:SYNVUL_BASE_URL="https://api.deepseek.com"
$env:SYNVUL_API_KEY="your_api_key"
$env:SYNVUL_MODEL="deepseek-chat"

.\.venv\Scripts\python -m synvulcommit.run_generation `
  --output output_production `
  --provider openai_compatible `
  --require-tools `
  --workers 4 `
  --max-attempts 8 `
  --per-cwe 100
```

The reviewer reuses the generation provider by default. `--review-provider` selects a separate provider configured through `SYNVUL_REVIEW_*` variables. `--no-review` and generation without `--require-tools` are diagnostic modes and should not be used to produce training data. A local/Ollama-style HTTP provider is also supported; see the [generation pipeline documentation](docs/generation_pipeline.md) for all environment variables.

Useful generation controls include:

- `--cwe sql --cwe xss` to restrict a run to selected modes;
- `--seed` to make quota planning deterministic;
- `--workers 1` for serial generation;
- `--no-export` to retain internal logs without rebuilding the VUDENC files.

### Generation Profiles

| Profile | Behavior |
| --- | --- |
| `compact` | Default. Small, self-contained files matching the existing generated corpus. |
| `window_balanced` | Requires 420-900 code tokens, localized badparts covering at most 15% of vulnerable tokens, positive and negative 200-token windows, and at least 75% fixed-code token retention. |

Select the larger profile with `--generation-profile window_balanced`. Profile-specific records are counted separately when resuming, and `single_function` quota slots are excluded from the window-balanced plan.

## Dataset Maintenance

Verify an existing generated output (the rejected log, VUDENC directory, and report path default to siblings of `samples.jsonl`):

```powershell
.\.venv\Scripts\python -m synvulcommit.verify_dataset `
  --input output_production\samples.jsonl
```

Rebuild the clean VUDENC export:

```powershell
.\.venv\Scripts\python -m synvulcommit.export_vudenc `
  --input output_production\samples.jsonl `
  --out output_production\vudenc
```

Revalidate an older output after validation rules change. The destination must be a new or empty directory; the source is left unchanged:

```powershell
.\.venv\Scripts\python -m synvulcommit.revalidate_dataset `
  --input output_old `
  --output output_revalidated `
  --require-tools `
  --workers 10
```

`samples.jsonl` and `rejected.jsonl` are audit logs, not direct model inputs. Model-facing files are `vudenc/plain_<mode>`; `vudenc/metadata.jsonl` is a sanitized provenance sidecar and should also be excluded from training.

## A/B/C Experiments

Install the experiment dependencies in the Lab 3 `vudenc` Conda environment, or another environment that can provide TensorFlow, Gensim, scikit-learn, PyTorch, and Transformers:

```powershell
python -m pip install -r requirements-experiments.txt
```

Prepare a frozen release from a verified synthetic JSONL and a local directory containing the real VUDENC `plain_*` files. This example matches the final reported 149-per-CWE selection; the CLI's smaller default remains 91:

```powershell
python -m synvulcommit.prepare_experiment `
  --synthetic output_production\samples.jsonl `
  --vudenc-root ..\data `
  --out experiments\release_149_v1 `
  --per-cwe 149 `
  --seed 20260624
```

Preparation selects synthetic records with marginal context balancing, caps real data at `min(per_cwe, available real commits)` per mode, assigns train/validation/test splits at commit level, and only then extracts 200-token windows. By default, at most four positive and four negative windows per file are retained.

The three conditions are:

| Condition | Training | Validation | Test |
| --- | --- | --- | --- |
| A | Real | Real | Held-out real |
| B | Synthetic | Synthetic | Same held-out real |
| C | Real + synthetic | Real | Same held-out real |

Run all eight variants used in the final reported comparison:

```powershell
python -m synvulcommit.run_experiments `
  --prepared experiments\release_149_v1 `
  --word2vec ..\w2v\word2vec_withString10-300-200.model `
  --models lstm mlp random_forest cnn `
           lstm_codebert cnn_codebert `
           lstm_graphcodebert cnn_graphcodebert
```

The CLI defaults to `lstm`, `cnn`, `mlp`, and `random_forest`. LSTM/CNN use 200-token Word2Vec sequences; MLP/Random Forest use mean-pooled 300-dimensional Word2Vec features.

The other four choices are frozen-transformer feature variants:

```text
lstm_codebert       cnn_codebert
lstm_graphcodebert  cnn_graphcodebert
```

Select them explicitly with `--models`. They use CodeBERT or GraphCodeBERT hidden states as 200-token sequences followed by the corresponding TensorFlow LSTM/CNN classifier. The encoders run under `no_grad` and are not fine-tuned.

Use `--smoke` for a short selected model path. Preparation writes manifests, audit samples, and `dataset_summary.json` under the release directory. Training writes `metrics.csv`, `comparison.md`, confusion matrices, cached features, and saved models beneath `<prepared>/results/` unless `--out` is supplied.

## Repository Layout

```text
.github/workflows/ci.yml       CI unit, strict-generation, export, and verification checks
synvulcommit/                  Generation, validation, export, verification, and experiment code
synvulcommit/rules/            Semgrep rules for the seven supported modes
tests/                         Unit, analyzer integration, pipeline, and optional live-review tests
docs/                          Detailed generation, dataset, and experiment documentation
scripts/make_report_figures.py Historical report-figure helper; requires local outputs not committed here
requirements.txt              Generator and validation dependencies
requirements-experiments.txt  Optional model-evaluation dependencies
project_desciption.txt        Original proposal (historical, not the current behavior contract)
```

Detailed references:

- [Generation pipeline](docs/generation_pipeline.md)
- [Dataset format and verification](docs/dataset.md)
- [A/B/C experiments and reported results](docs/experiments.md)

For exact options and defaults, run any module with `--help`.
