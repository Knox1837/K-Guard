#!/usr/bin/env python3
"""
Intent-aware validation benchmark.

This script loads the labeled scenario corpus, calibrates tfidf/embedding thresholds
on the calibration split, evaluates all backends on the held-out test split, and
emits a Markdown report plus JSON artifacts for inspection.
"""
from __future__ import annotations

import argparse
import json
import pickle
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

REPO_ROOT = Path(__file__).resolve().parents[2]
USER_SRC = REPO_ROOT / "src" / "user"
if str(USER_SRC) not in sys.path:
    sys.path.insert(0, str(USER_SRC))

from intent_validation_core import (  # noqa: E402
    EmbeddingIntentValidationBackend,
    IntentValidationConfig,
    KeywordIntentValidationBackend,
    TfidfIntentValidationBackend,
    calibrate_threshold,
    describe_sensitive_path,
    is_sensitive_path,
)

DATASET_PATH = Path(__file__).resolve().with_name("dataset.json")
ARTIFACT_DIR = Path(__file__).resolve().parent / "artifacts"
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR = Path(__file__).resolve().parent / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
GENERAL_CORPUS = [
    "Refactor application logic without touching secrets.",
    "Update documentation for the deployment pipeline.",
    "Check cache invalidation and routing behavior.",
    "Audit release notes and CI metadata.",
    "Adjust configuration for a web service.",
    "Review login failures in the staging environment.",
    "Inspect build logs and deployment scripts.",
    "Tune worker startup parameters.",
    "Rotate service credentials for a deployment bot.",
    "Validate SSH key handling for an admin host.",
]
BACKENDS = ("keyword", "tfidf", "embedding")


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    split: str
    category: str
    task_description: str
    accessed_path: str
    label: str
    rationale: str
    reviewed_by: str
    review_status: str


def read_rss_kb() -> int:
    status_path = Path("/proc/self/status")
    for line in status_path.read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return 0


def load_dataset() -> list[Scenario]:
    payload = json.loads(DATASET_PATH.read_text())
    scenarios = []
    for item in payload["scenarios"]:
        scenarios.append(Scenario(**item))
    return scenarios


def split_scenarios(scenarios: list[Scenario]) -> tuple[list[Scenario], list[Scenario]]:
    calibration = [scenario for scenario in scenarios if scenario.split == "calibration"]
    test = [scenario for scenario in scenarios if scenario.split == "test"]
    return calibration, test


def build_tfidf_vectorizer(calibration_scenarios: list[Scenario]) -> TfidfVectorizer:
    corpus = list(GENERAL_CORPUS)
    for scenario in calibration_scenarios:
        pattern = is_sensitive_path(scenario.accessed_path)
        if pattern is None:
            raise ValueError(f"Scenario {scenario.scenario_id} does not access a sensitive path")
        corpus.append(scenario.task_description)
        corpus.append(describe_sensitive_path(scenario.accessed_path, pattern))
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), lowercase=True)
    vectorizer.fit(corpus)
    return vectorizer


def save_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))


def compute_metrics(records: list[dict]) -> dict:
    tp = fp = tn = fn = 0
    for record in records:
        predicted_violation = bool(record["predicted_violation"])
        truth_violation = record["label"] == "violation"
        if predicted_violation and truth_violation:
            tp += 1
        elif predicted_violation and not truth_violation:
            fp += 1
        elif not predicted_violation and not truth_violation:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "tpr": recall,
        "fpr": fpr,
        "f1": f1,
    }


def category_breakdown(records: list[dict]) -> list[dict]:
    breakdown = []
    categories = sorted({record["category"] for record in records})
    for category in categories:
        subset = [record for record in records if record["category"] == category]
        metrics = compute_metrics(subset)
        breakdown.append(
            {
                "category": category,
                "count": len(subset),
                **metrics,
            }
        )
    return breakdown


def warmup_backend(backend, pattern: str) -> None:
    backend.is_justified("warmup calibration task", "/tmp/" + pattern.replace("/", "_") + "_placeholder", pattern)


def evaluate_backend(backend_name: str, calibration_scenarios: list[Scenario], test_scenarios: list[Scenario]) -> dict:
    rss_before = read_rss_kb()

    vectorizer_path = ARTIFACT_DIR / "tfidf_vectorizer.pkl"
    if backend_name == "keyword":
        backend = KeywordIntentValidationBackend()
        threshold = 0.5
        warmup_backend(backend, ".ssh/")
    elif backend_name == "tfidf":
        vectorizer = build_tfidf_vectorizer(calibration_scenarios)
        with vectorizer_path.open("wb") as handle:
            pickle.dump(vectorizer, handle)
        backend = TfidfIntentValidationBackend(vectorizer)
        warmup_backend(backend, ".ssh/")
        train_scores = []
        train_labels = []
        for scenario in calibration_scenarios:
            pattern = is_sensitive_path(scenario.accessed_path)
            score = backend.is_justified(scenario.task_description, scenario.accessed_path, pattern)
            train_scores.append(score)
            train_labels.append(1 if scenario.label == "violation" else 0)
        threshold, calibration_stats = calibrate_threshold(train_scores, train_labels)
    elif backend_name == "embedding":
        backend = EmbeddingIntentValidationBackend()
        warmup_backend(backend, ".ssh/")
        train_scores = []
        train_labels = []
        for scenario in calibration_scenarios:
            pattern = is_sensitive_path(scenario.accessed_path)
            score = backend.is_justified(scenario.task_description, scenario.accessed_path, pattern)
            train_scores.append(score)
            train_labels.append(1 if scenario.label == "violation" else 0)
        threshold, calibration_stats = calibrate_threshold(train_scores, train_labels)
    else:
        raise ValueError(f"Unknown backend {backend_name}")

    rss_after = read_rss_kb()
    rss_delta_kb = max(0, rss_after - rss_before)

    test_records = []
    for scenario in test_scenarios:
        pattern = is_sensitive_path(scenario.accessed_path)
        if pattern is None:
            raise ValueError(f"Scenario {scenario.scenario_id} does not access a sensitive path")
        started = time.perf_counter_ns()
        score = backend.is_justified(scenario.task_description, scenario.accessed_path, pattern)
        latency_ns = time.perf_counter_ns() - started
        test_records.append(
            {
                "scenario_id": scenario.scenario_id,
                "category": scenario.category,
                "label": scenario.label,
                "score": score,
                "predicted_violation": score < threshold,
                "latency_ns": latency_ns,
            }
        )

    metrics = compute_metrics(test_records)
    latencies_ns = [record["latency_ns"] for record in test_records]
    metrics.update(
        {
            "median_latency_us": float(np.median(latencies_ns) / 1000.0) if latencies_ns else 0.0,
            "p95_latency_us": float(np.percentile(latencies_ns, 95) / 1000.0) if latencies_ns else 0.0,
            "rss_delta_kb": rss_delta_kb,
        }
    )

    category_rows = category_breakdown(test_records)
    config = IntentValidationConfig(
        backend=backend_name,
        threshold=float(threshold),
        tfidf_vectorizer_path=str(vectorizer_path),
        embedding_model_name="sentence-transformers/all-MiniLM-L6-v2",
        source="benchmark",
    )
    config_path = ARTIFACT_DIR / f"intent_validation_{backend_name}.json"
    save_json(config_path, config.as_dict())

    return {
        "backend": backend_name,
        "config_path": str(config_path),
        "threshold": threshold,
        "calibration": calibration_stats if backend_name != "keyword" else {"threshold": threshold},
        "metrics": metrics,
        "category_rows": category_rows,
        "test_records": test_records,
        "rss_delta_kb": rss_delta_kb,
        "status": "ok",
    }


def render_summary(results: list[dict]) -> str:
    lines = [
        "# Intent-Aware Benchmark Results",
        "",
        "| Backend | Threshold | TP | FP | TN | FN | Precision | Recall | FPR | F1 | Median latency (us) | p95 latency (us) | RSS delta (KB) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for result in results:
        if result.get("status") != "ok":
            lines.append(f"| {result['backend']} | error | 0 | 0 | 0 | 0 | 0.000 | 0.000 | 0.000 | 0.000 | 0.00 | 0.00 | {result.get('rss_delta_kb', 0)} |")
            continue
        metrics = result["metrics"]
        lines.append(
            f"| {result['backend']} | {result['threshold']:.4f} | {metrics['tp']} | {metrics['fp']} | {metrics['tn']} | {metrics['fn']} | "
            f"{metrics['precision']:.3f} | {metrics['recall']:.3f} | {metrics['fpr']:.3f} | {metrics['f1']:.3f} | "
            f"{metrics['median_latency_us']:.2f} | {metrics['p95_latency_us']:.2f} | {metrics['rss_delta_kb']} |"
        )

    lines.extend(["", "## Per-Category Breakdown", ""])
    for result in results:
        lines.extend([f"### {result['backend']}", "", "| Category | Count | TP | FP | TN | FN | Precision | Recall | FPR | F1 |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"])
        for row in result["category_rows"]:
            lines.append(
                f"| {row['category']} | {row['count']} | {row['tp']} | {row['fp']} | {row['tn']} | {row['fn']} | "
                f"{row['precision']:.3f} | {row['recall']:.3f} | {row['fpr']:.3f} | {row['f1']:.3f} |"
            )
        lines.append("")

    return "\n".join(lines)


def run_worker(backend_name: str) -> dict:
    scenarios = load_dataset()
    calibration_scenarios, test_scenarios = split_scenarios(scenarios)
    if any(s.review_status != "approved" for s in scenarios):
        print("WARNING: benchmark scenarios are marked pending human review.", file=sys.stderr)
    return evaluate_backend(backend_name, calibration_scenarios, test_scenarios)


def run_parent() -> int:
    all_results = []
    for backend_name in BACKENDS:
        command = [sys.executable, str(Path(__file__).resolve()), "--worker", "--backend", backend_name]
        completed = subprocess.run(command, capture_output=True, text=True)
        if completed.returncode != 0:
            print(completed.stdout, end="")
            print(completed.stderr, end="", file=sys.stderr)
            all_results.append(
                {
                    "backend": backend_name,
                    "status": "error",
                    "error": completed.stderr.strip() or completed.stdout.strip(),
                    "metrics": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "precision": 0.0, "recall": 0.0, "tpr": 0.0, "fpr": 0.0, "f1": 0.0, "median_latency_us": 0.0, "p95_latency_us": 0.0, "rss_delta_kb": 0},
                    "category_rows": [],
                    "threshold": 0.0,
                }
            )
            continue
        payload = json.loads(completed.stdout)
        all_results.append(payload)

    results_json_path = RESULTS_DIR / "intent_aware_benchmark_results.json"
    results_md_path = RESULTS_DIR / "intent_aware_benchmark_results.md"
    save_json(results_json_path, {"results": all_results})
    results_md_path.write_text(render_summary(all_results))

    print(results_md_path)
    print(results_json_path)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the K-Guard intent-aware benchmark.")
    parser.add_argument("--worker", action="store_true", help="Run one backend and emit JSON to stdout.")
    parser.add_argument("--backend", choices=BACKENDS, help="Backend to evaluate in worker mode.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.worker:
        if not args.backend:
            raise SystemExit("--backend is required in worker mode")
        try:
            payload = run_worker(args.backend)
        except Exception as exc:  # pragma: no cover - benchmark runtime guard
            payload = {
                "backend": args.backend,
                "status": "error",
                "error": str(exc),
                "metrics": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "precision": 0.0, "recall": 0.0, "tpr": 0.0, "fpr": 0.0, "f1": 0.0, "median_latency_us": 0.0, "p95_latency_us": 0.0, "rss_delta_kb": 0},
                "category_rows": [],
                "threshold": 0.0,
            }
        print(json.dumps(payload))
        return 0
    return run_parent()


if __name__ == "__main__":
    raise SystemExit(main())