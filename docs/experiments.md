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

## Frozen Synthetic Subset

The generated corpus used for the final experiment contained enough accepted records to freeze a balanced release of:

```text
91 synthetic commit pairs per CWE
7 CWEs
637 total synthetic commit pairs
```

The selected subset is stratified by:

- application type,
- flow pattern,
- difficulty,
- program structure.

The selection uses a fixed seed so the subset is reproducible.

## Real VUDENC Normalization

The experiment loader normalizes the original VUDENC `plain_*` files and SynVulCommit exports into one commit-level representation.

Legacy VUDENC mode names are mapped to the seven SynVulCommit modes. In particular, path-disclosure-style data is mapped to `directory_traversal` for the Lab 5 comparison.

Per CWE, the real-data cap is:

```text
min(91, available real commits)
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

The final controlled comparison runs four model families:

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

CodeBERT and GraphCodeBERT were excluded from the primary Lab 5 comparison because the earlier Lab 3 transformer experiments were unstable. The controlled Lab 5 comparison therefore focuses on the four established Word2Vec model families.

## Commands

Prepare an experiment release:

```powershell
.\.venv\Scripts\python -m synvulcommit.prepare_experiment `
  --synthetic output_deepseekpro_glmreview_100_per_cwe\samples.jsonl `
  --vudenc-root ..\data `
  --out experiments\release_91_v1 `
  --per-cwe 91 `
  --seed 20260624
```

Run a CPU smoke test:

```powershell
python -m synvulcommit.run_experiments `
  --prepared experiments\release_91_v1 `
  --word2vec ..\w2v\word2vec_withString10-300-200.model `
  --smoke `
  --epochs 1
```

Run the full comparison:

```powershell
python -m synvulcommit.run_experiments `
  --prepared experiments\release_91_v1 `
  --word2vec ..\w2v\word2vec_withString10-300-200.model
```

The full experiment writes:

```text
experiments/release_91_v1/
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

## Final Result Summary

The final run showed that real-only training remained strongest overall. Synthetic-only training transferred poorly to the real VUDENC test set, mostly because synthetic generated files often produced too few clean negative windows under the 200-token VUDENC windowing setup. The combined real+synthetic condition slightly helped LSTM but did not consistently improve MLP, Random Forest, or CNN.

Mean macro-F1 by model family and condition:

| Model | A real-only | B synthetic-only | C real+synthetic |
| --- | ---: | ---: | ---: |
| CNN | 0.6124 | 0.3662 | 0.6080 |
| LSTM | 0.5407 | 0.4289 | 0.5605 |
| MLP | 0.6463 | 0.3577 | 0.6421 |
| Random Forest | 0.6618 | 0.3419 | 0.6415 |

The result does not mean the generator failed. It means the synthetic corpus is useful as a controlled data-generation artifact, but its distribution is not yet a drop-in replacement for real VUDENC commits under the exact Lab 3 window-labeling setup.

## Known Limitations

- Synthetic files are often shorter and more focused than real commits.
- Synthetic-only training creates a positive-heavy window distribution.
- The reviewer improves semantic confidence but cannot fully guarantee realism.
- The generated corpus is Python-only and tied to the seven VUDENC-style CWE modes.
- The experiment evaluates transfer to real VUDENC windows, not production vulnerability detection.

These limitations are discussed in the Lab 5 report.
