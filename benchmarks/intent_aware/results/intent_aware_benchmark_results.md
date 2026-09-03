# Intent-Aware Benchmark Results

| Backend | Threshold | TP | FP | TN | FN | Precision | Recall | FPR | F1 | Median latency (us) | p95 latency (us) | RSS delta (KB) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| keyword | 0.5000 | 10 | 0 | 10 | 0 | 1.000 | 1.000 | 0.000 | 1.000 | 1.03 | 3.35 | 0 |
| tfidf | 0.0188 | 8 | 0 | 10 | 2 | 1.000 | 0.800 | 0.000 | 0.889 | 615.16 | 683.15 | 964 |
| embedding | error | 0 | 0 | 0 | 0 | 0.000 | 0.000 | 0.000 | 0.000 | 0.00 | 0.00 | 0 |

## Per-Category Breakdown

### keyword

| Category | Count | TP | FP | TN | FN | Precision | Recall | FPR | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| benign_direct | 4 | 0 | 0 | 4 | 0 | 0.000 | 0.000 | 0.000 | 0.000 |
| benign_indirect | 5 | 1 | 0 | 4 | 0 | 1.000 | 1.000 | 0.000 | 1.000 |
| violation_adversarial | 5 | 4 | 0 | 1 | 0 | 1.000 | 1.000 | 0.000 | 1.000 |
| violation_blatant | 6 | 5 | 0 | 1 | 0 | 1.000 | 1.000 | 0.000 | 1.000 |

### tfidf

| Category | Count | TP | FP | TN | FN | Precision | Recall | FPR | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| benign_direct | 4 | 0 | 0 | 4 | 0 | 0.000 | 0.000 | 0.000 | 0.000 |
| benign_indirect | 5 | 0 | 0 | 4 | 1 | 0.000 | 0.000 | 0.000 | 0.000 |
| violation_adversarial | 5 | 3 | 0 | 1 | 1 | 1.000 | 0.750 | 0.000 | 0.857 |
| violation_blatant | 6 | 5 | 0 | 1 | 0 | 1.000 | 1.000 | 0.000 | 1.000 |

### embedding

| Category | Count | TP | FP | TN | FN | Precision | Recall | FPR | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
