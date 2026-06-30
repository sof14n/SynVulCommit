# SynVulCommit

SynVulCommit is the Lab 5 mini-project for generating and evaluating synthetic vulnerability-fixing commits. It creates paired vulnerable/fixed Python code for the seven VUDENC vulnerability modes, validates the pair with deterministic checks and security analyzers, optionally gates it with a second LLM reviewer, exports a clean VUDENC-style training format, and runs a controlled A/B/C comparison against real VUDENC data.

The repository contains the implementation, validation rules, tests, and reproducibility documentation. Generated datasets, provider logs, `.env` files, virtual environments, reports, trained models, and large experiment outputs are intentionally not committed.

## Project Scope

The project has two connected parts:

- **Dataset generator:** produces accepted vulnerable/fixed commit pairs with quota-based context coverage, duplicate rejection, deterministic validation, LLM review, VUDENC export, and dataset verification.
- **Evaluation pipeline:** prepares balanced real/synthetic commit splits and evaluates LSTM, MLP, Random Forest, and CNN models under three conditions: real-only, synthetic-only, and real+synthetic training.

Large reproducibility artifacts are published separately as GitHub Release assets. The submitted Lab 5 artifact release contains the final generated dataset, rejected-attempt audit log, VUDENC export, experiment manifests, metrics, and trained model outputs.

## Setup

Use Python 3.11 or 3.12. On Windows PowerShell:

```powershell
git clone https://github.com/sof14n/SynVulCommit.git
cd SynVulCommit
python -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install -r requirements.txt
```

For model experiments, install the optional experiment requirements in the Lab 3 `vudenc` Conda environment or another environment with TensorFlow, scikit-learn, Gensim, NumPy, and Joblib:

```powershell
python -m pip install -r requirements-experiments.txt
```

## Core Commands

Run the unit test suite:

```powershell
.\.venv\Scripts\python -m pytest
```

Run a small diagnostic generation job with a real OpenAI-compatible provider:

```powershell
$env:SYNVUL_BASE_URL="https://api.deepseek.com"
$env:SYNVUL_API_KEY="your_api_key"
$env:SYNVUL_MODEL="deepseek-chat"
.\.venv\Scripts\python -m synvulcommit.run_generation `
  --output output_pilot `
  --provider openai_compatible `
  --require-tools `
  --workers 4 `
  --max-attempts 8 `
  --per-cwe 2
```

Generation defaults to the compact profile used by the current datasets. To request longer modules for later window-balanced experiments, add:

```powershell
--generation-profile window_balanced
```

This profile is stricter and slower because accepted samples must contain 420-900 code tokens, localized badparts, and at least one positive and one negative 200-token source window.

Verify an existing generated dataset:

```powershell
.\.venv\Scripts\python -m synvulcommit.verify_dataset --input output_pilot\samples.jsonl
```

Re-export accepted samples to VUDENC format:

```powershell
.\.venv\Scripts\python -m synvulcommit.export_vudenc `
  --input output_pilot\samples.jsonl `
  --out output_pilot\vudenc
```

Prepare an A/B/C experiment dataset, assuming a generated synthetic JSONL exists locally. Choose `--per-cwe` based on the minimum accepted count available across the CWE modes you want to balance:

```powershell
.\.venv\Scripts\python -m synvulcommit.prepare_experiment `
  --synthetic output_pilot\samples.jsonl `
  --vudenc-root ..\data `
  --out experiments\<release_name> `
  --per-cwe <N> `
  --seed 20260624
```

Run the model comparison:

```powershell
python -m synvulcommit.run_experiments `
  --prepared experiments\<release_name> `
  --word2vec ..\w2v\word2vec_withString10-300-200.model
```

## Repository Structure

```text
synvulcommit/                 Generator, validation, export, verification, and experiment code
synvulcommit/rules/           SynVulCommit Semgrep rules for the seven CWE modes
tests/                        Unit and integration-style tests
docs/                         Detailed documentation
requirements.txt              Generator and validation dependencies
requirements-experiments.txt  Model evaluation dependencies
project_desciption.txt        Original project proposal/description
```

Detailed documentation:

- [Generation Pipeline](docs/generation_pipeline.md)
- [Dataset Format And Verification](docs/dataset.md)
- [A/B/C Experiments](docs/experiments.md)

## Notes On Mock Mode

The mock provider exists for parser and pipeline tests. It does not represent final dataset quality and is not a substitute for real provider generation. Because the production planner now enforces context-specific quota slots, static mock fixtures can become stale when validation rules change. Real production runs should use an actual provider plus strict validation and review.

## Artifacts And Submission

The GitHub repository is kept code-focused. Large generated artifacts are not tracked in Git.

The final dataset, rejected audit log, VUDENC export, trained model outputs, split manifests, metrics, and confusion matrices are provided as GitHub Release assets:

```text
https://github.com/sof14n/SynVulCommit/releases/tag/v1.0-lab5
```

The report is submitted separately through Overleaf and is intentionally excluded from this repository.

GitHub repository link:

```text
https://github.com/sof14n/SynVulCommit
```
