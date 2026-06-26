import networkx as nx
import numpy as np
import math
from sklearn.ensemble import IsolationForest

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

print("\n--- UPGRADED K-GUARD ML CONTENT-AWARE THREAT REPORT ---")
for i in range(len(node_list)):
    if predictions[i] == -1:
        print(f"⚠️ [ANOMALY DETECTED] Process: {node_list[i]}")
        print(f"   -> Max Path Length: {features[i][2]} chars | Max Randomness (Entropy): {features[i][3]:.2f}")
        if features[i][4] == 1:
            print("   -> 🚨 CRITICAL: This process explicitly touched a sensitive system target!")
