"""
Loads the saved CPG, extracts features via ml/features.py, fits an IsolationForest, and prints a threat report with root cause attribution.
"""

import sys
import os
from pathlib import Path

import networkx as nx
import numpy as np
import joblib
from pyvis import node

from . import config
from .features import extract_features

sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "user"), # to add src/user for provenance.py import
)
from provenance import find_root_cause, format_chain  # noqa: E402

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "output"
GEXF_FILE = OUTPUT_DIR / "system_behavior_graph.gexf"
MODEL_PATH = Path(__file__).resolve().parent / "models" / "baseline_model.joblib"

def load_graph(path: Path = GEXF_FILE) -> nx.DiGraph:
    print("Loading saved behavioral structure graph...")
    return nx.read_gexf(path)

def load_model(path: Path = MODEL_PATH):
    if not path.exists():
        raise FileNotFoundError(...)
    bundle = joblib.load(path)
    return bundle["model"], bundle.get("lof_model"), bundle.get("dbscan_model"), bundle["meta"]

def run_detection(G: nx.DiGraph):
    """Runs the ML anomaly detector on the given causal provenance graph and prints a report of any anomalies found"""
    X, node_list, feature_names = extract_features(G)
    print(f"Advanced data matrix prepared. Evaluated {X.shape[0]} footprints "
          f"with {X.shape[1]} metrics each: {feature_names}")

    if X.shape[0] == 0:
        print("No process nodes found in graph")
        return

    clf, lof, dbscan, meta = load_model()
    threshold = meta["threshold"]
    print(f"Using baseline model trained {meta['trained_at']} "
          f"(threshold={threshold:.4f}, target FPR={meta['threshold_fpr_target']:.2%})")
    scores = clf.decision_function(X)
    if_predictions = np.where(scores < threshold, -1, 1)

    lof_scores = None
    lof_predictions = np.ones(X.shape[0], dtype=int)
    if lof is not None and "lof_threshold" in meta:
        lof_threshold = meta["lof_threshold"]
        lof_scores = lof.decision_function(X)
        lof_predictions = np.where(lof_scores < lof_threshold, -1, 1)

    dbscan_scores = None
    dbscan_predictions = np.ones(X.shape[0], dtype=int)
    if dbscan is not None and "dbscan_threshold" in meta:
        dbscan_threshold = meta["dbscan_threshold"]
        dbscan_scores = dbscan.decision_function(X)
        dbscan_predictions = np.where(dbscan_scores < dbscan_threshold, -1, 1)

    vote_count = (
        (if_predictions == -1).astype(int)
        + (lof_predictions == -1).astype(int)
        + (dbscan_predictions == -1).astype(int)
    )
    MIN_VOTES = 2
    predictions = np.where(vote_count >= MIN_VOTES, -1, 1)

    print("\nK-GUARD ML CONTENT-AWARE THREAT REPORT")
    mttrc_samples = []
    len_idx = feature_names.index("max_len")
    entropy_idx = feature_names.index("max_entropy")
    sensitive_idx = feature_names.index("contains_sensitive")
    sent_idx = feature_names.index("total_bytes_sent_log")
    ratio_idx = feature_names.index("send_recv_ratio")
    correlated_idx = feature_names.index("sensitive_read_then_connect")

    for i, node in enumerate(node_list):
        sec_label = G.nodes[node].get("security_label")
        ml_flagged = predictions[i] == -1
        if not ml_flagged and not sec_label:
            continue  # skip only if NEITHER signal fired

        comm = G.nodes[node].get("comm", "unknown")
        print(f"[ANOMALY DETECTED] Process: {node}  comm={comm!r}")
        if ml_flagged:
            flagged_by = []
            if if_predictions[i] == -1:
                flagged_by.append(f"IsolationForest (score={scores[i]:.4f})")
            if lof_predictions[i] == -1:
                flagged_by.append(f"LOF (score={lof_scores[i]:.4f})")
            if dbscan_predictions[i] == -1:
                flagged_by.append(f"DBSCAN (score={dbscan_scores[i]:.4f})")
            print(f"   -> Flagged by: {', '.join(flagged_by)}")
        if sec_label:
            print(f"   -> KERNEL VERDICT: {sec_label} "
                f"(fd {G.nodes[node].get('socket_fd')} → stdio {G.nodes[node].get('redirected_fd')}, "
                f"dest={G.nodes[node].get('redirect_dest_ip')}:{G.nodes[node].get('redirect_dest_port')})")

                  
        print(f"    -> Max Path Length: {X[i][len_idx]} chars | "
              f"Max Randomness (Entropy): {X[i][entropy_idx]:.2f}")
        if X[i][sensitive_idx] == 1:
            print("   -> CRITICAL: This process explicitly touched a sensitive system target!")
        if X[i][correlated_idx] == 1:
            print("   -> CRITICAL: Sensitive file read immediately followed by an outbound "
                  "connection (read-then-exfil pattern)!")
        if X[i][sent_idx] > 0:
            print(f"   -> Outbound data sent (log-scaled): {X[i][sent_idx]:.2f}, "
                  f"send/recv ratio: {X[i][ratio_idx]:.2f}")

        root, chain, mttrc_ms = find_root_cause(G, node)
        mttrc_samples.append(mttrc_ms)

        if root is not None and root != node:
            print(f"   -> ROOT CAUSE: {root}")
            print(f"   -> CAUSAL CHAIN ({len(chain)} hops): {format_chain(chain)}")
        else:
            print("   -> ROOT CAUSE: no traceable parent — this process is the root")
        print(f"   -> MTTRC: {mttrc_ms:.3f} ms")

    if mttrc_samples:
        mean_mttrc = sum(mttrc_samples) / len(mttrc_samples)
        print(f"\nMean Time To Root Cause across {len(mttrc_samples)} alert(s): "
            f"{mean_mttrc:.3f} ms")

def main():
    G = load_graph()
    run_detection(G)

if __name__ == "__main__":
    main()