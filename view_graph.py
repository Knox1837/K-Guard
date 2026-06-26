import networkx as nx
import matplotlib.pyplot as plt

print("Loading your saved K-Guard system graph...")
# Load the graph structure file you generated
G = nx.read_gexf("system_behavior_graph.gexf")

if G.number_of_nodes() == 0:
    print("The graph file is empty! Run your monitor pipeline longer and generate data first.")
    exit()

print(f"Graph loaded successfully: {G.number_of_nodes()} nodes found.")
print("Rendering visual layout window...")

# Set up the visual window size
plt.figure(figsize=(12, 8))

# Calculate a spring-layout positioning (bubbles out nodes nicely)
pos = nx.spring_layout(G, k=0.3, iterations=50)

# Color-code nodes based on their type attributes
color_map = []
for node, data in G.nodes(data=True):
    node_type = data.get("type", "process")
    if node_type == "process":
        color_map.append("#ff4d4d")       # Red for active running processes
    elif node_type == "file_binary":
        color_map.append("#33cc33")   # Green for executable binaries
    else:
        color_map.append("#3399ff")       # Blue for accessed data files

# Draw the nodes, connections, and labels
nx.draw_networkx_nodes(G, pos, node_color=color_map, node_size=800, alpha=0.9)
nx.draw_networkx_edges(G, pos, width=1.5, alpha=0.6, edge_color="gray", arrows=True)
nx.draw_networkx_labels(G, pos, font_size=8, font_weight="bold")

plt.title("K-Guard Causal Provenance Graph (CPG) Map", fontsize=14)
plt.axis("off") # Hide graph grid lines

output_file = "graph.png"
plt.savefig(output_file, format="PNG", dpi=300, bbox_inches="tight")

print(f"Graph image rendered and saved successfully as '{output_file}'!")
