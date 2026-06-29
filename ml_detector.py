import sys
import os
import networkx as nx
import numpy as np
import math
from sklearn.ensemble import IsolationForest

# provenance.py lives in src/user/, add it to the path so this script can
# be run from the project root (matches how monitor.c / graphengine.py
# are already invoked).
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src", "user"))
from provenance import find_root_cause, format_chain

def calculate_entropy(s):
    """Calculates Shannon Entropy to evaluate string randomness (Character Model)."""
    if not s:
        return 0
    entropy = 0
    for x in set(s):
        p_x = float(s.count(x)) / len(s)
        entropy -= p_x * math.log(p_x, 2)
    return entropy

print("Loading saved behavioral structure graph...")
G = nx.read_gexf("system_behavior_graph.gexf")

features = []
node_list = []

for node, data in G.nodes(data=True):
    if data.get("type") == "process":
        # 1. Structural Features
        out_degree = G.out_degree(node)
        in_degree = G.in_degree(node)
        connections = out_degree + in_degree
        
        # 2. String/Argument Feature Extraction
        # Look at all files this specific process interacted with
        associated_files = [edge[1] for edge in G.edges(node)]
        
        max_len = 0
        max_entropy = 0
        contains_sensitive = 0
        
        for f in associated_files:
            # String Length Model
            if len(f) > max_len:
                max_len = len(f)
            # Character Distribution Model (Entropy)
            entropy = calculate_entropy(f)
            if entropy > max_entropy:
                max_entropy = entropy
            # Suspicious Target Keywords
            if any(kw in f for kw in ["shadow", "passwd", "secret", "root", ".ssh"]):
                contains_sensitive = 1
                
        # Combine structural data and string analytics into a comprehensive feature vector
        features.append([out_degree, connections, max_len, max_entropy, contains_sensitive])
        node_list.append(node)

X = np.array(features)
print(f"Advanced data matrix prepared. Evaluated {X.shape[0]} footprints with {X.shape[1]} metrics each.")

# Train the upgraded anomaly detector
clf = IsolationForest(contamination=0.05, random_state=42)
clf.fit(X)

predictions = clf.predict(X)

print("\nK-GUARD ML CONTENT-AWARE THREAT REPORT")
mttrc_samples = []
for i in range(len(node_list)):
    if predictions[i] == -1:
        alert_node = node_list[i]
        print(f"[ANOMALY DETECTED] Process: {alert_node}")
        print(f"    -> Max Path Length: {features[i][2]} chars | Max Randomness (Entropy): {features[i][3]:.2f}")
        if features[i][4] == 1:
            print("   -> CRITICAL: This process explicitly touched a sensitive system target!")

        # Root-Cause Attribution via reverse BFS on the CPG
        root, chain, mttrc_ms = find_root_cause(G, alert_node)
        mttrc_samples.append(mttrc_ms)

        if root is not None and root != alert_node:
            print(f"   -> ROOT CAUSE: {root}")
            print(f"   -> CAUSAL CHAIN ({len(chain)} hops): {format_chain(chain)}")
        else:
            print("   -> ROOT CAUSE: no traceable parent — this process is the root")
        print(f"   -> MTTRC: {mttrc_ms:.3f} ms")

if mttrc_samples:
    mean_mttrc = sum(mttrc_samples) / len(mttrc_samples)
    print(f"\n--- Mean Time To Root Cause across {len(mttrc_samples)} alert(s): {mean_mttrc:.3f} ms ---")
