"""
Usage:
    1. Run normal (non-attack) usage sessions through the existing monitor and copy the resulting output graph
        cp output/system_behavior_graph.gexf output/baseline_captures/session_2026-07-19_idle.gexf
        (run multiple times for better results, ideally with different clean workloads to capture a variety of normal behavior)
    2. Run:
    To train a new baseline model with guardrail for best model selection:
           python3 -m ml.train
           python -m ml.train --baseline-dir data/processed/clean
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
from .lof_novelty import LOFNoveltyScorer

from . import config
from .features import extract_features, FEATURE_NAMES
from .dbscan_novelty import DBSCANNoveltyScorer

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "output"
BASELINE_DIR = OUTPUT_DIR / "baseline_captures"
MODEL_DIR = Path(__file__).resolve().parent / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)
MODEL_PATH = MODEL_DIR / "baseline_model.joblib"

HOLDOUT_FRACTION = 0.2

# How strict the detection threshold is: the fraction of held-out CLEAN scores allowed to fall below the threshold
THRESHOLD_FPR = 0.01  # 1% of clean held-out nodes may still trip a threshold

MIN_SESSIONS_RECOMMENDED = 4
MIN_NODES_RECOMMENDED = 1000

_IF_THRESHOLD_FPR_DEFAULT = THRESHOLD_FPR
_IF_BEST_PARAMS_PATH = Path(__file__).resolve().parent / "if_best_params.json"

def _load_if_threshold_fpr() -> float:
    if _IF_BEST_PARAMS_PATH.exists():
        try:
            data = json.loads(_IF_BEST_PARAMS_PATH.read_text())
            fpr = float(data["threshold_fpr"])
            print(f"Using IF_THRESHOLD_FPR={fpr} from {_IF_BEST_PARAMS_PATH.name} "
                  f"(tuned {data.get('tuned_at', 'unknown date')}, "
                  f"actual_fpr={data.get('actual_fpr', 'n/a')})")
            return fpr
        except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
            print(f"WARNING: could not read {_IF_BEST_PARAMS_PATH.name} ({e}); "
                  f"falling back to default IF_THRESHOLD_FPR={_IF_THRESHOLD_FPR_DEFAULT}. "
                  f"Run `python -m ml.tune_if` to generate a real recommendation.")
            return _IF_THRESHOLD_FPR_DEFAULT
    else:
        print(f"No {_IF_BEST_PARAMS_PATH.name} found; using default "
              f"IF_THRESHOLD_FPR={_IF_THRESHOLD_FPR_DEFAULT} (same as shared THRESHOLD_FPR). "
              f"Run `python -m ml.tune_if` to calibrate this independently for your data.")
        return _IF_THRESHOLD_FPR_DEFAULT

IF_THRESHOLD_FPR = _load_if_threshold_fpr()

# LOF params (second, independent model)
# Default of 20 is a fallback only
# Tuned with `python -m ml.tune_lof` for particular data
_LOF_N_NEIGHBORS_DEFAULT = 20
_LOF_BEST_PARAMS_PATH = Path(__file__).resolve().parent / "lof_best_params.json"


def _load_lof_n_neighbors() -> int:
    if _LOF_BEST_PARAMS_PATH.exists():
        try:
            data = json.loads(_LOF_BEST_PARAMS_PATH.read_text())
            n = int(data["n_neighbors"])
            print(f"Using LOF_N_NEIGHBORS={n} from {_LOF_BEST_PARAMS_PATH.name} "
                  f"(tuned {data.get('tuned_at', 'unknown date')}, "
                  f"actual_fpr={data.get('actual_fpr', 'n/a')})")
            return n
        except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
            print(f"WARNING: could not read {_LOF_BEST_PARAMS_PATH.name} ({e}); "
                  f"falling back to default LOF_N_NEIGHBORS={_LOF_N_NEIGHBORS_DEFAULT}. "
                  f"Run `python -m ml.tune_lof` to generate a real recommendation.")
            return _LOF_N_NEIGHBORS_DEFAULT
    else:
        print(f"No {_LOF_BEST_PARAMS_PATH.name} found; using default "
              f"LOF_N_NEIGHBORS={_LOF_N_NEIGHBORS_DEFAULT}. "
              f"Run `python -m ml.tune_lof` to calibrate this for your data.")
        return _LOF_N_NEIGHBORS_DEFAULT


LOF_N_NEIGHBORS = _load_lof_n_neighbors()


def _load_lof_threshold_fpr() -> float:
    if _LOF_BEST_PARAMS_PATH.exists():
        try:
            data = json.loads(_LOF_BEST_PARAMS_PATH.read_text())
            fpr = float(data["threshold_fpr"])
            print(f"Using LOF_THRESHOLD_FPR={fpr} from {_LOF_BEST_PARAMS_PATH.name}")
            return fpr
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            pass
    print(f"No per-model threshold_fpr found for LOF; using shared THRESHOLD_FPR={THRESHOLD_FPR}. "
          f"Run `python -m ml.tune_lof` to calibrate LOF's own threshold_fpr.")
    return THRESHOLD_FPR


LOF_THRESHOLD_FPR = _load_lof_threshold_fpr()

# DBSCAN-style novelty scorer params (third independent model)
_DBSCAN_MIN_SAMPLES_DEFAULT = 20
_DBSCAN_BEST_PARAMS_PATH = Path(__file__).resolve().parent / "dbscan_best_params.json"


def _load_dbscan_min_samples() -> int:
    if _DBSCAN_BEST_PARAMS_PATH.exists():
        try:
            data = json.loads(_DBSCAN_BEST_PARAMS_PATH.read_text())
            n = int(data["min_samples"])
            print(f"Using DBSCAN_MIN_SAMPLES={n} from {_DBSCAN_BEST_PARAMS_PATH.name} "
                  f"(tuned {data.get('tuned_at', 'unknown date')}, "
                  f"actual_fpr={data.get('actual_fpr', 'n/a')})")
            return n
        except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
            print(f"WARNING: could not read {_DBSCAN_BEST_PARAMS_PATH.name} ({e}); "
                  f"falling back to default DBSCAN_MIN_SAMPLES={_DBSCAN_MIN_SAMPLES_DEFAULT}. "
                  f"Run `python -m ml.tune_dbscan` to generate a real recommendation.")
            return _DBSCAN_MIN_SAMPLES_DEFAULT
    else:
        print(f"No {_DBSCAN_BEST_PARAMS_PATH.name} found; using default "
              f"DBSCAN_MIN_SAMPLES={_DBSCAN_MIN_SAMPLES_DEFAULT}. "
              f"Run `python -m ml.tune_dbscan` to calibrate this for your data.")
        return _DBSCAN_MIN_SAMPLES_DEFAULT

DBSCAN_MIN_SAMPLES = _load_dbscan_min_samples()

def _load_dbscan_threshold_fpr() -> float:
    if _DBSCAN_BEST_PARAMS_PATH.exists():
        try:
            data = json.loads(_DBSCAN_BEST_PARAMS_PATH.read_text())
            fpr = float(data["threshold_fpr"])
            print(f"Using DBSCAN_THRESHOLD_FPR={fpr} from {_DBSCAN_BEST_PARAMS_PATH.name}")
            return fpr
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            pass
    print(f"No per-model threshold_fpr found for DBSCAN; using shared THRESHOLD_FPR={THRESHOLD_FPR}. "
          f"Run `python -m ml.tune_dbscan` to calibrate DBSCAN's own threshold_fpr.")
    return THRESHOLD_FPR

DBSCAN_THRESHOLD_FPR = _load_dbscan_threshold_fpr()

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

    print(f"Fitting LocalOutlierFactor (scaled + clipped) on {X_train.shape[0]} rows x {X_train.shape[1]} features...")
    lof = LOFNoveltyScorer(n_neighbors=LOF_N_NEIGHBORS, contamination=config.CONTAMINATION)
    lof.fit(X_train)
    n_neighbors = lof._effective_n_neighbors

    print(f"Fitting DBSCAN-style novelty scorer on {X_train.shape[0]} rows x {X_train.shape[1]} features "
          f"(min_samples={DBSCAN_MIN_SAMPLES})...")
    dbscan_min_samples_effective = min(DBSCAN_MIN_SAMPLES, max(1, X_train.shape[0] - 1))
    dbscan = DBSCANNoveltyScorer(min_samples=dbscan_min_samples_effective)
    dbscan.fit(X_train)

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
    threshold = float(np.percentile(holdout_scores, IF_THRESHOLD_FPR * 100))

    actual_fpr = float(np.mean(holdout_scores < threshold))
    print(
        f"Held-out clean score stats: min={holdout_scores.min():.4f} "
        f"mean={holdout_scores.mean():.4f} max={holdout_scores.max():.4f}"
    )
    print(f"Chosen threshold: {threshold:.4f} (empirical FPR on held-out clean data: {actual_fpr:.3%}, target: {IF_THRESHOLD_FPR:.3%})")

    # LOF gets its own independent threshold, using its own tuned threshold_fpr.
    lof_scores = lof.decision_function(X_holdout)
    lof_threshold = float(np.percentile(lof_scores, LOF_THRESHOLD_FPR * 100))
    lof_actual_fpr = float(np.mean(lof_scores < lof_threshold))
    print(
        f"Held-out clean LOF score stats: min={lof_scores.min():.4f} "
        f"mean={lof_scores.mean():.4f} max={lof_scores.max():.4f}"
    )
    print(f"Chosen LOF threshold: {lof_threshold:.4f} (empirical FPR on held-out clean data: {lof_actual_fpr:.3%}, target: {LOF_THRESHOLD_FPR:.3%})")

    # DBSCAN-style scorer gets its own independent threshold, using its own tuned threshold_fpr.
    dbscan_scores = dbscan.decision_function(X_holdout)
    dbscan_threshold = float(np.percentile(dbscan_scores, DBSCAN_THRESHOLD_FPR * 100))
    dbscan_actual_fpr = float(np.mean(dbscan_scores < dbscan_threshold))
    print(
        f"Held-out clean DBSCAN score stats: min={dbscan_scores.min():.4f} "
        f"mean={dbscan_scores.mean():.4f} max={dbscan_scores.max():.4f}"
    )
    print(f"Chosen DBSCAN threshold: {dbscan_threshold:.4f} (empirical FPR on held-out clean data: {dbscan_actual_fpr:.3%}, target: {DBSCAN_THRESHOLD_FPR:.3%})")

    # Ensemble score: combine all three raw scores via the same z-score normalization used at training time
    if_mean, if_std = float(holdout_scores.mean()), float(holdout_scores.std()) or 1e-9
    lof_mean, lof_std = float(lof_scores.mean()), float(lof_scores.std()) or 1e-9
    dbscan_mean, dbscan_std = float(dbscan_scores.mean()), float(dbscan_scores.std()) or 1e-9

    z_if = (holdout_scores - if_mean) / if_std
    z_lof = (lof_scores - lof_mean) / lof_std
    z_dbscan = (dbscan_scores - dbscan_mean) / dbscan_std
    ensemble_holdout_scores = (z_if + z_lof + z_dbscan) / 3.0

    ensemble_threshold = float(np.percentile(ensemble_holdout_scores, threshold_fpr * 100))
    ensemble_actual_fpr = float(np.mean(ensemble_holdout_scores < ensemble_threshold))
    print(
        f"Held-out clean ENSEMBLE (avg z-score) stats: min={ensemble_holdout_scores.min():.4f} "
        f"mean={ensemble_holdout_scores.mean():.4f} max={ensemble_holdout_scores.max():.4f}"
    )
    print(f"Chosen ENSEMBLE threshold: {ensemble_threshold:.4f} (empirical FPR on held-out clean data: {ensemble_actual_fpr:.3%})")

    metadata = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "feature_names": FEATURE_NAMES,
        "contamination": config.CONTAMINATION,
        "random_state": seed,
        "threshold": threshold,
        "threshold_fpr_target": IF_THRESHOLD_FPR,
        "threshold_fpr_actual_holdout": actual_fpr,
        "lof_n_neighbors": n_neighbors,
        "lof_threshold": lof_threshold,
        "lof_threshold_fpr_actual_holdout": lof_actual_fpr,
        "dbscan_min_samples": dbscan_min_samples_effective,
        "dbscan_threshold": dbscan_threshold,
        "dbscan_threshold_fpr_actual_holdout": dbscan_actual_fpr,
        "ensemble_if_mean": if_mean, "ensemble_if_std": if_std,
        "ensemble_lof_mean": lof_mean, "ensemble_lof_std": lof_std,
        "ensemble_dbscan_mean": dbscan_mean, "ensemble_dbscan_std": dbscan_std,
        "ensemble_threshold": ensemble_threshold,
        "ensemble_threshold_fpr_actual_holdout": ensemble_actual_fpr,
        "n_train_rows": int(X_train.shape[0]),
        "n_holdout_rows": int(X_holdout.shape[0]),
        "train_sessions": [p.name for p in train_paths],
        "holdout_sessions": [p.name for p in holdout_paths],
    }

    versioned_path = model_path.with_name(
        f"{model_path.stem}_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}{model_path.suffix}"
    )
    # Both models are saved side by side under distinct keys. LOF is additive and it does not replace or overwrite the "model" (IsolationForest) key.
    joblib.dump({"model": clf, "lof_model": lof, "dbscan_model": dbscan, "meta": metadata}, versioned_path)

    meta_path = versioned_path.with_suffix(".json")
    meta_path.write_text(json.dumps(metadata, indent=2))
    print(f"Saved model to {versioned_path}")
    print(f"Saved metadata to {meta_path}")

    current_meta_path = model_path.with_suffix(".json")

    # Each model is promoted independently if its own threshold FPR is better than the currently active model's FPR, and if it was trained on at least half as many rows as the currently active model.
    promote_if = True
    promote_lof = True
    promote_dbscan = True
    current_model = None
    current_lof_model = None
    current_dbscan_model = None
    current_meta = None

    if model_path.exists() and current_meta_path.exists() and not force:
        try:
            current_meta = json.loads(current_meta_path.read_text())
            current_fpr = current_meta.get("threshold_fpr_actual_holdout")
            current_lof_fpr = current_meta.get("lof_threshold_fpr_actual_holdout")
            current_dbscan_fpr = current_meta.get("dbscan_threshold_fpr_actual_holdout")
            current_rows = current_meta.get("n_train_rows", 0)
            new_fpr = metadata["threshold_fpr_actual_holdout"]
            new_lof_fpr = metadata["lof_threshold_fpr_actual_holdout"]
            new_dbscan_fpr = metadata["dbscan_threshold_fpr_actual_holdout"]
            new_rows = metadata["n_train_rows"]

            rows_much_smaller = new_rows < current_rows * 0.5
            if_fpr_worse = current_fpr is not None and new_fpr > current_fpr
            lof_fpr_worse = current_lof_fpr is not None and new_lof_fpr > current_lof_fpr
            dbscan_fpr_worse = current_dbscan_fpr is not None and new_dbscan_fpr > current_dbscan_fpr

            promote_if = not (if_fpr_worse or rows_much_smaller)
            promote_lof = not (lof_fpr_worse or rows_much_smaller)
            promote_dbscan = not (dbscan_fpr_worse or rows_much_smaller)

            if not promote_if or not promote_lof or not promote_dbscan:
                # Load the currently active bundle so we can keep whichever
                # model(s) this run did NOT beat.
                current_bundle = joblib.load(model_path)
                current_model = current_bundle.get("model")
                current_lof_model = current_bundle.get("lof_model")
                current_dbscan_model = current_bundle.get("dbscan_model")

            if not promote_if:
                print(
                    "\nNOT promoting IsolationForest from this run:\n"
                    f"  current: if_fpr={current_fpr:.3%} rows={current_rows}\n"
                    f"  new:     if_fpr={new_fpr:.3%} rows={new_rows}\n"
                    "This run's IsolationForest looks worse than (or trained on much "
                    "less data than) the currently active one. Keeping the existing "
                    "IsolationForest in baseline_model.joblib. Re-run with --force to "
                    "override."
                )
            if not promote_lof:
                print(
                    "\nNOT promoting LOF from this run:\n"
                    f"  current: lof_fpr={current_lof_fpr if current_lof_fpr is not None else 'n/a'} rows={current_rows}\n"
                    f"  new:     lof_fpr={new_lof_fpr:.3%} rows={new_rows}\n"
                    "This run's LOF looks worse than (or trained on much less data "
                    "than) the currently active one. Keeping the existing LOF in "
                    "baseline_model.joblib. Re-run with --force to override."
                )
            if not promote_dbscan:
                print(
                    "\nNOT promoting DBSCAN from this run:\n"
                    f"  current: dbscan_fpr={current_dbscan_fpr if current_dbscan_fpr is not None else 'n/a'} rows={current_rows}\n"
                    f"  new:     dbscan_fpr={new_dbscan_fpr:.3%} rows={new_rows}\n"
                    "This run's DBSCAN scorer looks worse than (or trained on much "
                    "less data than) the currently active one. Keeping the existing "
                    "DBSCAN model in baseline_model.joblib. Re-run with --force to "
                    "override."
                )
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Could not read existing model metadata ({e}); promoting new models.")

    final_model = clf if promote_if else current_model
    final_lof_model = lof if promote_lof else current_lof_model
    final_dbscan_model = dbscan if promote_dbscan else current_dbscan_model

    final_meta = dict(metadata)
    if not promote_if and current_meta is not None:
        for k in ("threshold", "threshold_fpr_actual_holdout"):
            if k in current_meta:
                final_meta[k] = current_meta[k]
    if not promote_lof and current_meta is not None:
        for k in ("lof_n_neighbors", "lof_threshold", "lof_threshold_fpr_actual_holdout"):
            if k in current_meta:
                final_meta[k] = current_meta[k]
    if not promote_dbscan and current_meta is not None:
        for k in ("dbscan_min_samples", "dbscan_threshold", "dbscan_threshold_fpr_actual_holdout"):
            if k in current_meta:
                final_meta[k] = current_meta[k]

    # Ensemble z-score stats are only valid if ALL THREE underlying models came from this same run 
    all_three_promoted_together = promote_if and promote_lof and promote_dbscan
    if not all_three_promoted_together:
        ensemble_keys = (
            "ensemble_if_mean", "ensemble_if_std", "ensemble_lof_mean", "ensemble_lof_std",
            "ensemble_dbscan_mean", "ensemble_dbscan_std", "ensemble_threshold",
            "ensemble_threshold_fpr_actual_holdout",
        )
        if current_meta is not None and all(k in current_meta for k in ensemble_keys):
            for k in ensemble_keys:
                final_meta[k] = current_meta[k]
            print(
                "\nNOTE: models were promoted individually (mixed old/new), so this "
                "run's ensemble z-score stats were NOT used (they'd describe a "
                "combination of models not actually in the active bundle). Kept "
                "the previous ensemble calibration instead. Re-run with --force "
                "if you want a fully consistent fresh ensemble."
            )
        else:
            print(
                "\nWARNING: models were promoted individually (mixed old/new) and "
                "no previous ensemble stats exist to fall back on. This run's "
                "ensemble stats were saved anyway, but may not accurately reflect "
                "the actual combination of models in the active bundle. Re-run "
                "with --force for a fully consistent ensemble."
            )

    joblib.dump({"model": final_model, "lof_model": final_lof_model, "dbscan_model": final_dbscan_model, "meta": final_meta}, model_path)
    current_meta_path.write_text(json.dumps(final_meta, indent=2))

    promoted = []
    if promote_if:
        promoted.append("IsolationForest")
    if promote_lof:
        promoted.append("LOF")
    if promote_dbscan:
        promoted.append("DBSCAN")
    if promoted:
        print(f"Updated latest-model pointer at {model_path} ({', '.join(promoted)} promoted)")
    else:
        print(f"Active model at {model_path} left unchanged (no model improved).")

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