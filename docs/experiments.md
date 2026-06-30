# A/B/C Model Evaluation

This document separates the current experiment code contract from the historical final Lab 5 run. Prepared releases, VUDENC inputs, Word2Vec data, downloaded transformer weights, trained models, and raw metrics are not committed in the current repository.

## Experiment Question

Every selected model is evaluated under the same three data conditions:

| Condition | Training data | Validation data | Test data |
| --- | --- | --- | --- |
| A | real VUDENC train | real VUDENC validation | held-out real VUDENC test |
| B | synthetic train | synthetic validation | the same held-out real VUDENC test |
| C | real + synthetic train | real VUDENC validation | the same held-out real VUDENC test |

The fixed real test split makes the comparison about training data. Condition B intentionally uses synthetic validation while still measuring transfer on real test windows.

## External Inputs

The workflow requires files that are intentionally absent from the repository:

- an accepted synthetic `samples.jsonl`;
- its `dataset_verification.json` for provenance;
- original real VUDENC `plain_*` files;
- a Python Word2Vec model, normally `../w2v/word2vec_withString10-300-200.model`, or the source corpus used to rebuild one;
- network/cache access to Hugging Face model weights when transformer variants are selected.

Verify the synthetic source before preparation. `prepare_experiment` copies an available verification report into the release audit directory, but it does not inspect or enforce that report's pass status.

## Preparation CLI And Defaults

Preparation uses only the package and Python standard library:

```powershell
python -m synvulcommit.prepare_experiment [options]
```

| Option | Default |
| --- | --- |
| `--synthetic` | `output_deepseekpro_glmreview_100_per_cwe/samples.jsonl` |
| `--vudenc-root` | `../data` |
| `--out` | `experiments/release_91_v1` |
| `--per-cwe` | `91` |
| `--seed` | `20260624` |
| `--window-size` | `200` |
| `--stride` | `5` |
| `--max-positive-windows` | `4` per file |
| `--max-negative-windows` | `4` per file |
| `--synthetic-verification` | sibling `dataset_verification.json` when present |

These are CLI defaults, not immutable experiment constants. The final reported run used `--per-cwe 149`, described separately below.

## Input Normalization And Selection

Synthetic records are loaded from internal accepted JSONL. Unknown modes are skipped. Each synthetic record becomes one file/commit record with repository alias `synvulcommit` and its four context dimensions.

Real records are loaded from every `plain_*` file under `--vudenc-root`. The only legacy mode alias implemented by the loader is:

```text
path_disclosure -> directory_traversal
```

A real commit may contain several file records. All files share a `group_id` built from dataset, canonical mode, repository, and commit ID.

Synthetic selection requires at least `--per-cwe` candidates for every one of the seven modes. It greedily selects a deterministic subset by minimizing, in order, full-context and marginal context counts, followed by a seed-based SHA-256 rank. This is marginal balancing, not a statistical stratified sample.

Real selection caps commit groups—not file rows—at:

```text
min(per_cwe, available real commit groups)
```

All files belonging to a selected real commit are retained, so real file-record counts can exceed real commit counts.

## Commit Splits

Splits are assigned before window extraction and grouped by `group_id`. Real and synthetic records are split independently within each mode using a deterministic seed rank and an approximately 70/15/15 train/validation/test allocation.

This prevents windows from one commit crossing splits. The model runner requires non-empty real train, real validation, real test, synthetic train, and synthetic validation windows for every selected mode; otherwise it exits before training that mode.

## Token Windows And Labels

The tokenizer is the repository's Python-like lexical regular expression, not Python's `tokenize` module or a model tokenizer. It recognizes identifiers, numbers, common multi-character operators, and remaining non-whitespace characters.

For each vulnerable source file:

1. window starts advance by `--stride`, with a final end-aligned start added when necessary;
2. each window contains up to `--window-size` tokens, so short files still produce one shorter window;
3. a window is positive (`label=1`) when its source span overlaps any occurrence of a `badpart`;
4. all other source windows are negative (`label=0`);
5. each label is deterministically capped per file using the configured positive/negative maxima.

Only vulnerable source is windowed. Fixed source and `goodparts` remain in commit manifests but are not model features.

Each window row records `group_id`, dataset, mode, commit/repository/filename, context, token strings, label, and split.

## Prepared Release Layout

Preparation writes:

```text
<release>/
  dataset_summary.json
  manifests/
    synthetic_selected.jsonl
    real_selected.jsonl
    commit_splits.jsonl
    windows.jsonl
  audit/
    synthetic_pairs_for_manual_review.jsonl
    source_dataset_verification.json  # only when a source report exists
```

The manual-review file selects up to five context-diverse synthetic pairs per mode and marks them `pending_manual_review`; preparation does not claim that manual review occurred.

`dataset_summary.json` records seed, selection target, modes, synthetic/real commit and file counts, selected/unbounded window counts, split counts, and total positive/negative windows.

## Model Runner

Install `requirements-experiments.txt` in the Lab 3 `vudenc` Conda environment or an equivalent ML environment. The runner imports Joblib, NumPy, TensorFlow, Gensim, and scikit-learn for every run. PyTorch and Transformers are additionally needed when a transformer variant is selected.

```powershell
python -m synvulcommit.run_experiments [options]
```

Important defaults:

| Option | Default |
| --- | --- |
| `--prepared` | `experiments/release_91_v1` |
| `--out` | `<prepared>/results` |
| `--word2vec` | `../w2v/word2vec_withString10-300-200.model` |
| `--word2vec-corpus` | `../w2v/pythontraining.txt` |
| `--models` | `lstm mlp random_forest cnn` |
| `--conditions` | `A B C` |
| `--modes` | all seven canonical modes |
| `--seed` | `20260624` |
| `--epochs` | `100` for TensorFlow classifiers |
| `--batch-size` | `128` |
| `--transformer-batch-size` | `16` during transformer feature extraction |

`--smoke` forces one TensorFlow epoch, one MLP iteration, or one Random Forest tree for the selected paths.

## Word2Vec Features And Models

The runner first tries to load the supplied Gensim Word2Vec model. If loading fails, it reuses `<out>/word2vec/word2vec_rebuilt_10-5-300.model` or rebuilds a 300-dimensional model from `--word2vec-corpus` with window 10, minimum count 10, four workers, five epochs, and the selected seed.

The four default variants are:

| Name | Feature representation | Classifier |
| --- | --- | --- |
| `lstm` | 200 Word2Vec vocabulary IDs with a frozen embedding matrix | LSTM(100), dropout 0.2, sigmoid output |
| `cnn` | 200 Word2Vec vocabulary IDs with a frozen embedding matrix | Conv1D(128, kernel 5), global max pool, dense 128, dropout 0.2, sigmoid output |
| `mlp` | Mean of in-vocabulary Word2Vec vectors | scikit-learn MLP with hidden layers 256/128, ReLU, Adam, max 500 iterations |
| `random_forest` | Mean of in-vocabulary Word2Vec vectors | 300 trees, balanced class weights, parallel fitting |

Out-of-vocabulary tokens become zero/padding in sequence features and are omitted from mean pooling. A row with no known tokens receives an all-zero pooled vector.

The TensorFlow LSTM/CNN models use Adam, binary cross-entropy, batch size 128 by default, and early stopping with patience 10 on a custom validation F1 callback. The MLP and Random Forest do not use the validation split for early stopping.

## Frozen Transformer Variants

Four additional choices are implemented:

| Name | Encoder | Classifier head |
| --- | --- | --- |
| `lstm_codebert` | `microsoft/codebert-base` | TensorFlow LSTM(100) |
| `cnn_codebert` | `microsoft/codebert-base` | TensorFlow CNN |
| `lstm_graphcodebert` | `microsoft/graphcodebert-base` | TensorFlow LSTM(100) |
| `cnn_graphcodebert` | `microsoft/graphcodebert-base` | TensorFlow CNN |

The window's first 200 lexical tokens are joined into text and passed to the Hugging Face tokenizer with padding/truncation length 200. The PyTorch encoder runs in evaluation mode under `no_grad`; its full last hidden state is cached as a float array. Only the TensorFlow LSTM/CNN head is trained. The encoder is not fine-tuned.

Transformer feature extraction can require substantial memory and disk. `--transformer-batch-size` controls encoder extraction batches; `--batch-size` controls TensorFlow classifier training.

## Metrics And Output Layout

Every selected model/condition/mode is tested on the same real test rows for that mode. The runner records accuracy, positive-class precision/recall/F1, macro-F1, total/positive support, and a 2x2 confusion matrix.

With default output placement, training adds:

```text
<release>/results/
  metrics.csv
  metrics.json
  comparison.md
  confusion_matrices/
  feature_cache/
  models/
  word2vec/                 # only when a model is rebuilt
```

`comparison.md` averages macro-F1 across the selected modes for each model/condition. Neural models are saved as `.keras`; MLP and Random Forest models are saved with Joblib.

## Example Commands

Prepare a release matching the final reported 149-per-CWE selection:

```powershell
python -m synvulcommit.prepare_experiment `
  --synthetic output_production\samples.jsonl `
  --vudenc-root ..\data `
  --out experiments\release_149_v1 `
  --per-cwe 149 `
  --seed 20260624
```

Run all eight reported variants:

```powershell
python -m synvulcommit.run_experiments `
  --prepared experiments\release_149_v1 `
  --word2vec ..\w2v\word2vec_withString10-300-200.model `
  --models lstm mlp random_forest cnn `
           lstm_codebert cnn_codebert `
           lstm_graphcodebert cnn_graphcodebert
```

Run a narrow CPU smoke path:

```powershell
python -m synvulcommit.run_experiments `
  --prepared experiments\release_149_v1 `
  --word2vec ..\w2v\word2vec_withString10-300-200.model `
  --models random_forest `
  --conditions A `
  --modes sql `
  --smoke
```

## Final Reported Run

The final report snapshot recorded a verified window-balanced corpus of 1,205 accepted pairs:

| Mode | Accepted corpus | Selected synthetic | Selected real commits |
| --- | ---: | ---: | ---: |
| SQL injection | 149 | 149 | 149 |
| Command injection | 179 | 149 | 106 |
| Directory traversal | 160 | 149 | 140 |
| Open redirect | 167 | 149 | 93 |
| Remote code execution | 191 | 149 | 54 |
| XSS | 159 | 149 | 69 |
| XSRF | 200 | 149 | 141 |

The balanced synthetic subset therefore contained 1,043 records. The run evaluated all eight variants. Its recorded mean macro-F1 across the seven CWEs was:
```text
experiments/<release_name>/
  audit/
  features/
  manifests/
  models/
  results/
  dataset_summary.json
```

Important result files:

```text
results/metrics.csv
results/comparison.md
results/confusion_matrices/
```

## Result Interpretation

Use the generated `results/metrics.csv`, `results/comparison.md`, and confusion matrices for conclusions. In general, compare:

- A vs. B to test whether synthetic-only training transfers to real VUDENC data,
- A vs. C to test whether synthetic data improves a real-data baseline,
- per-CWE scores to avoid hiding category-specific behavior behind aggregate metrics.

The submitted Lab 5 run showed that synthetic data is most useful as controlled augmentation, not as a direct replacement for real vulnerability-fixing commits. Exact metrics are provided in the release artifact bundle and in the submitted report.

| Model | A real-only | B synthetic-only | C mixed |
| --- | ---: | ---: | ---: |
| LSTM Word2Vec | 0.5709 | 0.4408 | 0.6175 |
| MLP Word2Vec | 0.6848 | 0.4333 | **0.7161** |
| Random Forest Word2Vec | 0.6984 | 0.4585 | 0.6637 |
| CNN Word2Vec | 0.6477 | 0.3961 | 0.6073 |
| LSTM CodeBERT | 0.4663 | 0.4881 | 0.4666 |
| CNN CodeBERT | 0.5992 | 0.4415 | 0.5591 |
| LSTM GraphCodeBERT | 0.5098 | 0.4919 | 0.5524 |
| CNN GraphCodeBERT | 0.6140 | 0.4201 | 0.6232 |

These are historical reported results, not a fresh run from the current clone: the raw release, model files, and result CSV were removed from version control. Reproduction requires the external inputs listed above.
- Synthetic files can still differ from real commits in style and distribution.
- Synthetic-only training may not transfer cleanly to real VUDENC test windows.
- The reviewer improves semantic confidence but cannot fully guarantee realism.
- The generated corpus is Python-only and tied to the seven VUDENC-style CWE modes.
- The experiment evaluates transfer to real VUDENC windows, not production vulnerability detection.

The strongest recorded configuration was mixed-training Word2Vec MLP at 0.7161 mean macro-F1. Synthetic-only training was below the corresponding real-only result for every variant except LSTM CodeBERT, whose three results were all relatively weak. Frozen transformer representations did not outperform the strongest Word2Vec models.

## Limitations

- Dataset acceptance favors explicit patterns that deterministic checks and an LLM reviewer can recognize; this can narrow the synthetic distribution.
- Window labels are overlap labels derived from changed vulnerable fragments, not exploitability labels.
- The real test sets are relatively small for modes with few real commits, especially RCE and XSS in the reported run.
- Transformer encoders are frozen feature extractors rather than fine-tuned models.
- The final reported comparison used one split/training seed; it does not estimate run-to-run variance.
- The project covers Python and seven VUDENC-style modes only.
- Evaluation measures transfer to held-out VUDENC windows, not production deployment performance.
