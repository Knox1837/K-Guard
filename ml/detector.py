"""
Loads the saved CPG, extracts features via ml/features.py, fits an IsolationForest, and prints a threat report with root cause attribution.
"""

import sys
import os
from pathlib import Path

import networkx as nx
import numpy as np
import joblib

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
        raise FileNotFoundError(
            f"No trained baseline model at {path}. Run `python3 -m ml.train` "
            f"first (see ml/train.py docstring for how to capture baseline data)."
        )
    bundle = joblib.load(path)
    return bundle["model"], bundle["meta"]

def run_detection(G: nx.DiGraph):
    """Runs the ML anomaly detector on the given causal provenance graph and prints a report of any anomalies found"""
    X, node_list, feature_names = extract_features(G)
    print(f"Advanced data matrix prepared. Evaluated {X.shape[0]} footprints "
          f"with {X.shape[1]} metrics each: {feature_names}")

    if X.shape[0] == 0:
        print("No process nodes found in graph")
        return

    clf, meta = load_model()
    threshold = meta["threshold"]
    print(f"Using baseline model trained {meta['trained_at']} "
          f"(threshold={threshold:.4f}, target FPR={meta['threshold_fpr_target']:.2%})")

    scores = clf.decision_function(X)  # continuous anomaly score, not a forced quota
    predictions = np.where(scores < threshold, -1, 1)

    print("\nK-GUARD ML CONTENT-AWARE THREAT REPORT")
    mttrc_samples = []
    len_idx = feature_names.index("max_len")
    entropy_idx = feature_names.index("max_entropy")
    sensitive_idx = feature_names.index("contains_sensitive")
    sent_idx = feature_names.index("total_bytes_sent_log")
    ratio_idx = feature_names.index("send_recv_ratio")
    correlated_idx = feature_names.index("sensitive_read_then_connect")

    for i, node in enumerate(node_list):
        if predictions[i] != -1:
            continue

        print(f"[ANOMALY DETECTED] Process: {node}")
        # Surface the kernel's own verdict first, if it has one
        sec_label = G.nodes[node].get("security_label")
        if sec_label:
            print(f"   -> KERNEL VERDICT: {sec_label} "
                  f"(fd {G.nodes[node].get('socket_fd')} → stdio {G.nodes[node].get('redirected_fd')})")
                  
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