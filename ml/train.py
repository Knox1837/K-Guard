"""
ml/train.py

Usage:
    1. Run normal (non-attack) usage sessions through the existing monitor and copy the resulting output graph
        cp output/system_behavior_graph.gexf output/baseline_captures/session_2026-07-19_idle.gexf
        (run multiple times for better results, ideally with different clean workloads to capture a variety of normal behavior)
    2. Run:
    To train a new baseline model with guardrail for best model selection:
           python3 -m ml.train
    To force update the model:
           python3 -m ml.train --force  
         - saves the model + threshold + metadata to ml/baseline_model.joblib
"""

from __future__ import annotations
import argparse
import json
import random
from datetime import datetime, timezone
from pathlib import Path

import networkx as nx
import numpy as np

try:
    import joblib
except ImportError as e:
    raise SystemExit(
        "joblib is required for train.py (pip install joblib --break-system-packages)"
    ) from e

from sklearn.ensemble import IsolationForest

from . import config
from .features import extract_features, FEATURE_NAMES

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "output"
BASELINE_DIR = OUTPUT_DIR / "baseline_captures"
MODEL_DIR = Path(__file__).resolve().parent / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)
MODEL_PATH = MODEL_DIR / "baseline_model.joblib"

HOLDOUT_FRACTION = 0.2

# How strict the detection threshold is: the fraction of held-out CLEAN scores allowed to fall below the threshold (i.e. your accepted false positive rate on data you already know is normal)
THRESHOLD_FPR = 0.01  # 1% of clean held-out nodes may still trip a threshold

MIN_SESSIONS_RECOMMENDED = 4
MIN_NODES_RECOMMENDED = 1000


def _load_session_features(gexf_path: Path) -> np.ndarray:
    G = nx.read_gexf(gexf_path)
    X, _, _ = extract_features(G)
    return X


def _split_sessions(gexf_paths: list[Path], holdout_fraction: float, seed: int):
    paths = list(gexf_paths)
    rng = random.Random(seed)
    rng.shuffle(paths)

    n_holdout = max(1, round(len(paths) * holdout_fraction)) if len(paths) > 1 else 0
    holdout = paths[:n_holdout]
    train = paths[n_holdout:]

    # Guard against holding out everything when there are very few sessions
    if not train:
        train, holdout = paths, []

    return train, holdout


def train_baseline(
    baseline_dir: Path = BASELINE_DIR,
    model_path: Path = MODEL_PATH,
    holdout_fraction: float = HOLDOUT_FRACTION,
    threshold_fpr: float = THRESHOLD_FPR,
    seed: int = config.RANDOM_STATE,
    force: bool = False,
) -> dict:
    gexf_paths = sorted(baseline_dir.glob("*.gexf"))
    if not gexf_paths:
        raise FileNotFoundError(
            f"No .gexf files found in {baseline_dir}. Capture some clean "
            f"sessions first (see module docstring)."
        )

    if len(gexf_paths) < MIN_SESSIONS_RECOMMENDED:
        print(
            f"WARNING: only {len(gexf_paths)} baseline session(s) found. "
            f"{MIN_SESSIONS_RECOMMENDED}+ diverse clean sessions are recommended "
            f"for a reliable baseline -- proceeding anyway, but treat this "
            f"model as provisional."
        )

    train_paths, holdout_paths = _split_sessions(gexf_paths, holdout_fraction, seed)

    print(f"Training sessions ({len(train_paths)}): {[p.name for p in train_paths]}")
    print(f"Held-out sessions ({len(holdout_paths)}): {[p.name for p in holdout_paths]}")

    train_X_parts = [_load_session_features(p) for p in train_paths]
    train_X_parts = [x for x in train_X_parts if x.shape[0] > 0]
    if not train_X_parts:
        raise ValueError("No process nodes extracted from any training session.")
    X_train = np.vstack(train_X_parts)

    if X_train.shape[0] < MIN_NODES_RECOMMENDED:
        print(
            f"WARNING: only {X_train.shape[0]} training rows extracted. "
            f"{MIN_NODES_RECOMMENDED}+ rows recommended -- results may be noisy."
        )

    print(f"Fitting IsolationForest on {X_train.shape[0]} rows x {X_train.shape[1]} features...")
    clf = IsolationForest(
        contamination=config.CONTAMINATION,
        random_state=seed,
        n_estimators=200,
    )
    clf.fit(X_train)

    if holdout_paths:
        holdout_X_parts = [_load_session_features(p) for p in holdout_paths]
        holdout_X_parts = [x for x in holdout_X_parts if x.shape[0] > 0]
        X_holdout = np.vstack(holdout_X_parts) if holdout_X_parts else np.empty((0, X_train.shape[1]))
    else:
        print(
            "WARNING: no sessions held out; deriving threshold from training "
            "scores. This threshold will likely be too permissive -- capture "
            "more baseline sessions and retrain when possible."
        )
        X_holdout = X_train

    if X_holdout.shape[0] == 0:
        raise ValueError("Held-out set produced zero rows; cannot calibrate threshold.")

    holdout_scores = clf.decision_function(X_holdout)
    threshold = float(np.percentile(holdout_scores, threshold_fpr * 100))

    actual_fpr = float(np.mean(holdout_scores < threshold))
    print(
        f"Held-out clean score stats: min={holdout_scores.min():.4f} "
        f"mean={holdout_scores.mean():.4f} max={holdout_scores.max():.4f}"
    )
    print(f"Chosen threshold: {threshold:.4f} (empirical FPR on held-out clean data: {actual_fpr:.3%})")

    metadata = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "feature_names": FEATURE_NAMES,
        "contamination": config.CONTAMINATION,
        "random_state": seed,
        "threshold": threshold,
        "threshold_fpr_target": threshold_fpr,
        "threshold_fpr_actual_holdout": actual_fpr,
        "n_train_rows": int(X_train.shape[0]),
        "n_holdout_rows": int(X_holdout.shape[0]),
        "train_sessions": [p.name for p in train_paths],
        "holdout_sessions": [p.name for p in holdout_paths],
    }

    versioned_path = model_path.with_name(
        f"{model_path.stem}_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}{model_path.suffix}"
    )
    joblib.dump({"model": clf, "meta": metadata}, versioned_path)

    meta_path = versioned_path.with_suffix(".json")
    meta_path.write_text(json.dumps(metadata, indent=2))
    print(f"Saved model to {versioned_path}")
    print(f"Saved metadata to {meta_path}")

    current_meta_path = model_path.with_suffix(".json")
    should_promote = True
    if model_path.exists() and current_meta_path.exists() and not force:
        try:
            current_meta = json.loads(current_meta_path.read_text())
            current_fpr = current_meta.get("threshold_fpr_actual_holdout")
            current_rows = current_meta.get("n_train_rows", 0)
            new_fpr = metadata["threshold_fpr_actual_holdout"]
            new_rows = metadata["n_train_rows"]

            fpr_worse = current_fpr is not None and new_fpr > current_fpr
            rows_much_smaller = new_rows < current_rows * 0.5

            if fpr_worse or rows_much_smaller:
                should_promote = False
                print(
                    "\nNOT promoting this run to the active baseline_model.joblib:\n"
                    f"  current: fpr={current_fpr:.3%} rows={current_rows}\n"
                    f"  new:     fpr={new_fpr:.3%} rows={new_rows}\n"
                    "This run looks worse than (or trained on much less data than) "
                    "the currently active model. The versioned files above were "
                    "still saved -- re-run with --force to promote it anyway."
                )
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Could not read existing model metadata ({e}); promoting new model.")

    if should_promote:
        joblib.dump({"model": clf, "meta": metadata}, model_path)
        current_meta_path.write_text(json.dumps(metadata, indent=2))
        print(f"Updated latest-model pointer at {model_path}")
    else:
        print(f"Active model at {model_path} left unchanged.")

    return metadata


def main():
    parser = argparse.ArgumentParser(description="Train the K-Guard IsolationForest baseline.")
    parser.add_argument(
        "--baseline-dir", type=Path, default=BASELINE_DIR,
        help="Directory of clean .gexf session captures (default: output/baseline_captures)",
    )
    parser.add_argument(
        "--holdout-fraction", type=float, default=HOLDOUT_FRACTION,
        help="Fraction of sessions held out for threshold calibration (default: 0.2)",
    )
    parser.add_argument(
        "--threshold-fpr", type=float, default=THRESHOLD_FPR,
        help="Target false-positive rate on held-out clean data (default: 0.01)",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Promote this run to the active baseline_model.joblib even if it "
             "looks worse than (or trained on much less data than) the current one.",
    )
    args = parser.parse_args()

    args.baseline_dir.mkdir(parents=True, exist_ok=True)
    train_baseline(
        baseline_dir=args.baseline_dir,
        holdout_fraction=args.holdout_fraction,
        threshold_fpr=args.threshold_fpr,
        force=args.force,
    )


if __name__ == "__main__":
    main()