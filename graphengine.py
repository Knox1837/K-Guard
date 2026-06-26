import sys
import json
import networkx as nx

# Initialize our Directed Causal Provenance Graph
G = nx.DiGraph()

# Noise Filter: Ignore these highly repetitive background processes
NOISE_FILTER = {"systemd", "systemd-journal", "dbus-daemon", "packagekitd"}

print("Python Graph Engine Active. Awaiting streamed data pipeline...", flush=True)

try:
    # Read the data line-by-line straight out of the C program pipe
    for line in sys.stdin:
        try:
            event = json.loads(line.strip())
            
            pid = event["pid"]
            comm = event["comm"]
            target = event["target"]
            event_type = event["type"]

            if "/usr/lib/python3" in target:
                target = "/usr/lib/python3.14/*"
            elif "/site-packages/" in target:
                target = ".../site-packages/*"
                
            # Drop the event if it matches our background noise filter
            if comm in NOISE_FILTER:
                continue

            # Create an identity tracking label for the active process node
            process_node = f"{comm} (PID:{pid})"

            if event_type == "EXEC":
                # Create nodes and a directed execution edge
                # Meaning: Parent Process -> Spawns -> Target Binary
                G.add_node(process_node, type="process")
                G.add_node(target, type="file_binary")
                G.add_edge(process_node, target, relation="EXECUTES")
                
                print(f"[GRAPH ADD] Process {process_node} executed {target}")

            elif event_type == "OPEN":
                # Create nodes and a directed file-access edge
                # Meaning: Process -> Interacts with -> Target File
                G.add_node(process_node, type="process")
                G.add_node(target, type="file_data")
                G.add_edge(process_node, target, relation="OPENS")
                
                print(f"[GRAPH ADD] Process {process_node} read/wrote file {target}")

            # Print out the live stats of our expanding security graph structure
            print(f" -> Current Graph Scale: {G.number_of_nodes()} Nodes, {G.number_of_edges()} Edges")

        except json.JSONDecodeError:
            continue # Safely skip any bad or malformed text lines

except KeyboardInterrupt:
    print("\nStopping engine. Exporting security graph state...")
    # Save the graph data structure to disk so Day 13's ML can read it later!
    nx.write_gexf(G, "system_behavior_graph.gexf")
    print("Graph saved successfully as 'system_behavior_graph.gexf'.")
