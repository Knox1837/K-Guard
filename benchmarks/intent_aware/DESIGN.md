# Intent-Aware Benchmark Design

This benchmark evaluates three interchangeable Section 3.6.3 backends:

- `keyword`: the historical curated keyword rule, preserved as the zero-config default.
- `tfidf`: a lightweight cosine-similarity backend built from `TfidfVectorizer`.
- `embedding`: a local sentence-embedding backend using `sentence-transformers/all-MiniLM-L6-v2`.

## Why `all-MiniLM-L6-v2`

`all-MiniLM-L6-v2` is small, CPU-friendly, and widely used. It gives a practical
embedding baseline without introducing a GPU dependency or a large model footprint.
It still requires a one-time model download and cache population, after which
inference runs offline.

## Threshold calibration

The benchmark splits scenarios into calibration and test sets. The calibration split
is used to pick the similarity threshold that maximizes F1 for the violation class.
The chosen threshold and backend metadata are written to
`benchmarks/intent_aware/artifacts/intent_validation_<backend>.json`.

For `tfidf`, the vectorizer is fit on the calibration task descriptions plus a small
general corpus and cached to `benchmarks/intent_aware/artifacts/tfidf_vectorizer.pkl`.

## Limitations

- The dataset is intentionally small and synthetic, so it is useful for comparative
  evaluation but not for claims of real-world generalization.
- Scenarios are single open events, not multi-step agent traces.
- The benchmark is English-only.
- Scenario labels are marked as pending human review until a team member signs off
  on the final corpus.
