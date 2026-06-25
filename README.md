# SynVulCommit

SynVulCommit is the Lab 5 mini-project for generating and evaluating synthetic vulnerability-fixing commits. It creates paired vulnerable/fixed Python code for the seven VUDENC vulnerability modes, validates the pair with deterministic checks and security analyzers, optionally gates it with a second LLM reviewer, exports a clean VUDENC-style training format, and runs a controlled A/B/C comparison against real VUDENC data.

The repository contains the implementation and report sources. Generated datasets, provider logs, `.env` files, virtual environments, and large experiment outputs are intentionally not committed.

## Project Scope

The project has two connected parts:

- **Dataset generator:** produces accepted vulnerable/fixed commit pairs with quota-based context coverage, duplicate rejection, deterministic validation, LLM review, VUDENC export, and dataset verification.
- **Evaluation pipeline:** prepares balanced real/synthetic commit splits and evaluates LSTM, MLP, Random Forest, and CNN models under three conditions: real-only, synthetic-only, and real+synthetic training.

The final balanced synthetic experiment release used 91 accepted pairs per CWE, 637 pairs total, selected from a verified generated corpus.

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

Prepare the A/B/C experiment dataset, assuming a generated synthetic JSONL exists locally:

```powershell
.\.venv\Scripts\python -m synvulcommit.prepare_experiment `
  --synthetic output_pilot\samples.jsonl `
  --vudenc-root ..\data `
  --out experiments\release_91_v1 `
  --per-cwe 91 `
  --seed 20260624
```

Run the model comparison:

```powershell
python -m synvulcommit.run_experiments `
  --prepared experiments\release_91_v1 `
  --word2vec ..\w2v\word2vec_withString10-300-200.model
```

## Repository Structure

```text
synvulcommit/                 Generator, validation, export, verification, and experiment code
synvulcommit/rules/           SynVulCommit Semgrep rules for the seven CWE modes
tests/                        Unit and integration-style tests
scripts/                      Report figure generation helpers
docs/                         Detailed documentation
report/                       Lab report LaTeX sources and figures
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

## Report And Submission

The Lab 5 instructions require:

- an ACM-style research paper prepared in Overleaf,
- the Overleaf project shared with the instructors by July 1, 2026,
- code uploaded to GitHub and the repository link shared by July 1, 2026.

Report sources are in [report/acm_submission.tex](report/acm_submission.tex). The supporting body and references are split into [report/paper_body.tex](report/paper_body.tex) and [report/references.tex](report/references.tex). Figures are in [report/images](report/images).

GitHub repository link:

```text
https://github.com/sof14n/SynVulCommit
```
