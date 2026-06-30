# A/B/C Model Evaluation

This document describes the controlled model comparison used for the Lab 5 report.

## Goal

The experiment tests whether synthetic SynVulCommit data can substitute for or complement real VUDENC data when training classical vulnerability-detection models.

The comparison uses three training conditions:

| Condition | Training Data | Validation Data | Test Data |
| --- | --- | --- | --- |
| A | real VUDENC | real VUDENC | held-out real VUDENC |
| B | synthetic SynVulCommit | synthetic SynVulCommit | same held-out real VUDENC |
| C | real + synthetic | real VUDENC | same held-out real VUDENC |

The fixed real test split is reused for A, B, and C. This makes the comparison about training data, not test-set differences.

## Synthetic Subset Selection

The experiment preparation command selects a balanced synthetic subset from an accepted SynVulCommit `samples.jsonl` file. Choose `--per-cwe` according to the minimum accepted count available across the CWE modes being compared.

For example, `--per-cwe 100` selects up to 100 accepted synthetic commit groups per CWE. The selected subset is stratified by:

- application type,
- flow pattern,
- difficulty,
- program structure.

The selection uses a fixed seed so the subset is reproducible.

For the submitted Lab 5 run, the balanced subset was selected from a larger verified window-balanced generated corpus. The exact selected counts, split manifests, metrics, and trained outputs are distributed as GitHub Release artifacts rather than tracked in the source repository.

## Real VUDENC Normalization

The experiment loader normalizes the original VUDENC `plain_*` files and SynVulCommit exports into one commit-level representation.

Legacy VUDENC mode names are mapped to the seven SynVulCommit modes. In particular, path-disclosure-style data is mapped to `directory_traversal` for the Lab 5 comparison.

Per CWE, the real-data cap is:

```text
min(<synthetic per-CWE cap>, available real commits)
```

This keeps Model A and Model B as close as possible in commit count.

## Split Strategy

Splits are made at the commit level before source-window extraction. This prevents leakage where windows from one commit appear in both training and test sets.

Each window manifest row preserves:

- source dataset,
- commit group,
- CWE mode,
- split,
- label.

Changed vulnerable regions are labeled positive. Surrounding unchanged source windows are labeled negative.

The real VUDENC test split is frozen and reused for every condition.

## Windowing And Features

The experiment follows the Lab 3 VUDENC-style Word2Vec setup:

- 300-dimensional Python Word2Vec embeddings,
- 200-token sequence windows for LSTM and CNN,
- mean-pooled 300-dimensional vectors for MLP and Random Forest.

The Word2Vec artifact expected by the command is:

```text
..\w2v\word2vec_withString10-300-200.model
```

The sequence cache stores token ids and loads fixed vectors inside the neural models. This avoids large repeated floating-point feature caches.

To keep the CPU experiment tractable, preparation keeps a deterministic maximum of four positive and four negative windows per file when available.

## Models

The controlled comparison supports the four Word2Vec model families from the earlier lab:

- LSTM: 100 units, dropout 0.2.
- MLP: dense hidden layers 256 and 128 with ReLU and Adam.
- Random Forest: 300 trees with balanced class weights.
- CNN: 1D token-sequence CNN with 128 filters, kernel size 5, global max pooling, dense 128, dropout 0.2.

Neural models use:

- Adam,
- batch size 128,
- up to 100 epochs,
- early stopping on validation F1.

Python, NumPy, scikit-learn, and TensorFlow seeds are fixed for reproducibility.

The implementation also supports frozen CodeBERT and GraphCodeBERT embedding variants for LSTM and CNN. These transformer-embedding runs are optional because they are slower and create large feature caches.

## Commands

Prepare an experiment release:

```powershell
.\.venv\Scripts\python -m synvulcommit.prepare_experiment `
  --synthetic output_<run_name>\samples.jsonl `
  --vudenc-root ..\data `
  --out experiments\<release_name> `
  --per-cwe <N> `
  --seed 20260624
```

Run a CPU smoke test:

```powershell
python -m synvulcommit.run_experiments `
  --prepared experiments\<release_name> `
  --word2vec ..\w2v\word2vec_withString10-300-200.model `
  --smoke `
  --epochs 1
```

Run the full comparison:

```powershell
python -m synvulcommit.run_experiments `
  --prepared experiments\<release_name> `
  --word2vec ..\w2v\word2vec_withString10-300-200.model
```

The full experiment writes:

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

## Known Limitations

- Synthetic files can still differ from real commits in style and distribution.
- Synthetic-only training may not transfer cleanly to real VUDENC test windows.
- The reviewer improves semantic confidence but cannot fully guarantee realism.
- The generated corpus is Python-only and tied to the seven VUDENC-style CWE modes.
- The experiment evaluates transfer to real VUDENC windows, not production vulnerability detection.

These limitations are discussed in the Lab 5 report.
