import sys
import json
import time
import networkx as nx
from pyvis.network import Network

# Initialize Directed Causal Provenance Graph
G = nx.DiGraph()

# Noise Filter
NOISE_FILTER = {"systemd", "systemd-journal", "dbus-daemon", "packagekitd"}

TYPE_EXEC = 1
TYPE_FORK = 2
TYPE_EXIT = 3
TYPE_OPEN = 4
TYPE_TCP_CONNECT = 5

last_render_time = time.time()

# --- Section 3.4.4 Memory Management: TTL-based pruning ---------------------
# Kernel timestamps (timestamp_ns from bpf_ktime_get_ns()) are nanoseconds
# since boot, NOT wall-clock time — so we can't compare them against
# Python's time.time(). Instead we track the latest event timestamp we've
# seen and use THAT as our reference "now" for TTL purposes. Wall-clock
# time.time() is only used to gate how often we bother running the prune
# sweep at all, which is a totally separate concern.
TTL_NS = 30 * 60 * 1_000_000_000   # 30 minutes, matches Section 3.4.4 default
PRUNE_INTERVAL_SEC = 60            # how often (real seconds) we run a prune pass

node_last_seen = {}      # node_id -> latest timestamp_ns that touched it
latest_event_ts = 0      # the newest timestamp_ns observed from any event so far
last_prune_time = time.time()


def touch(node_id, ts):
    """Record that `node_id` was touched by an event at kernel time `ts`."""
    global latest_event_ts
    # FIX: must check `is None`, not `not ts` — ts=0 is a legitimate kernel
    # timestamp (nanoseconds since boot can genuinely be 0 in test data, or
    # vanishingly close to it on a real system), and `not 0` is True in
    # Python, which was silently dropping that event from tracking entirely.
    if ts is None:
        return
    node_last_seen[node_id] = ts
    if ts > latest_event_ts:
        latest_event_ts = ts


def prune_graph():
    """Remove nodes (and their incident edges) untouched for longer than TTL_NS.
    """
    if latest_event_ts == 0:
        return
    cutoff = latest_event_ts - TTL_NS
    stale = [n for n, ts in node_last_seen.items() if ts < cutoff]
    for n in stale:
        if G.has_node(n):
            G.remove_node(n)   # networkx drops incident edges automatically
        del node_last_seen[n]
    if stale:
        print(f"[PRUNE] Removed {len(stale)} node(s) older than the {TTL_NS // 60_000_000_000}-minute TTL", flush=True)


def export_interactive_graph(graph_obj):
    """Transforms our composite NetworkX graph into an interactive browser deployment."""
    # Create a PyVis network object with dark mode and smooth physics
    net = Network(height="800px", width="100%", bgcolor="#222222", font_color="white", directed=True)
    # Instead of default 1000, set to 150
    net.set_options("""
    var options = {
      "physics": {
        "solver": "barnesHut",
        "barnesHut": {
          "gravitationalConstant": -2000,
          "centralGravity": 0.3,
          "springLength": 95,
          "springConstant": 0.04,
          "damping": 0.85
        },
        "stabilization": {
          "enabled": true,
          "iterations": 150,
          "fit": true
        }
      }
    }
    """)

    for node, attrs in graph_obj.nodes(data=True):
        node_type = attrs.get("type", "unknown")
        
        # Format Node Visual Style and Labels based on Section 3.4 Criteria
        if node_type == "process":
            label = f"{attrs.get('comm')} (PID:{attrs.get('pid')})"
            title = f"Process: {attrs.get('comm')}\nPID: {attrs.get('pid')}\nUID: {attrs.get('uid')}\nGID: {attrs.get('gid')}\nStart Vector: {node[1]}"
            color = "#ff7675" # Pastel Red for Active Processes
            shape = "dot"
            size = 25
        elif node_type == "file_binary":
            label = node.split("/")[-1] if "/" in str(node) else str(node)
            title = f"Binary Target:\n{node}"
            color = "#74b9ff" # Light Blue for Executable Files
            shape = "diamond"
            size = 20
        elif node_type == "file_data":
            label = node.split("/")[-1] if "/" in str(node) else str(node)
            title = f"Data File Access:\n{node}"
            color = "#55efc4" # Pastel Green for Reads/Writes
            shape = "square"
            size = 15
        elif node_type == "network_socket":
            label = str(node)
            title = f"Outbound Network Destination:\nIP: {attrs.get('ip')}\nPort: {attrs.get('port')}"
            color = "#a29bfe" # Purple for Sockets
            shape = "triangle"
            size = 20
        else:
            label = str(node)
            title = "Unknown Node Context"
            color = "#dfe6e9"
            shape = "dot"
            size = 10

        # Relabel our complex tuple key (pid, start_time) to a safe string index
        safe_node_id = f"proc_{node[0]}_{node[1]}" if isinstance(node, tuple) else str(node)
        net.add_node(safe_node_id, label=label, title=title, color=color, shape=shape, size=size)

    # Translate Edges into the PyVis interface
    for source, target, edge_attrs in graph_obj.edges(data=True):
        safe_source = f"proc_{source[0]}_{source[1]}" if isinstance(source, tuple) else str(source)
        safe_target = f"proc_{target[0]}_{target[1]}" if isinstance(target, tuple) else str(target)
        
        relation = edge_attrs.get("relation", "")
        extra_info = f"\nFD: {edge_attrs.get('fd')}" if "fd" in edge_attrs else ""
        
        net.add_edge(
            safe_source, 
            safe_target, 
            label=relation, 
            title=f"Action: {relation}{extra_info}\nTime: {edge_attrs.get('timestamp')}",
            color="#ffeaa7" # Warm yellow tracking paths
        )

    # Save out as an interactive standalone web application webpage layout
    net.save_graph("kguard_interactive_graph.html")
    freeze_physics_after_stabilization("kguard_interactive_graph.html")


def freeze_physics_after_stabilization(html_path):
    """Patch the saved HTML so physics stops once the layout settles."""
    try:
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()

        freeze_script = """
<script type="text/javascript">
  if (typeof network !== "undefined") {
    network.once("stabilizationIterationsDone", function () {
        network.setOptions({ physics: false });
    });
  }
</script>
"""
        if "</body>" in html:
            html = html.replace("</body>", freeze_script + "</body>")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html)
    except (FileNotFoundError, OSError) as e:
        print(f"[WARN] Could not patch physics-freeze script into {html_path}: {e}", flush=True)


print("Python Live Interactive Graph Engine Active. Monitoring system...", flush=True)

try:
    for line in sys.stdin:
        try:
            event = json.loads(line.strip())
            type_id = event.get("type_id")
            comm = event.get("comm", "unknown")
            pid = event.get("pid")
            
            if comm in NOISE_FILTER:
                continue

            start_time = event.get("start_time_ns", 0)
            process_node_id = (pid, start_time)
            ts = event.get("timestamp_ns")  # FIX: default None (missing), not 0 — see touch()

            # 1. EXECUTION HANDLING 
            if type_id == TYPE_EXEC:
                target = event.get("target", "unknown")
                if "/usr/lib/python3" in target: target = "/usr/lib/python3.14/*"
                elif "/site-packages/" in target: target = ".../site-packages/*"

                G.add_node(process_node_id, type="process", comm=comm, pid=pid, uid=event.get("uid"), gid=event.get("gid"))
                G.add_node(target, type="file_binary")
                G.add_edge(process_node_id, target, relation="EXECUTES", timestamp=ts)
                touch(process_node_id, ts)
                touch(target, ts)

            # 2. FORK HANDLING 
            elif type_id == TYPE_FORK:
                child_pid = event.get("child_pid")
                child_node_id = (child_pid, start_time) 

                if not G.has_node(process_node_id):
                    G.add_node(process_node_id, type="process", comm=comm, pid=pid)
                
                G.add_node(child_node_id, type="process", comm=comm, pid=child_pid)
                G.add_edge(process_node_id, child_node_id, relation="FORKED", timestamp=ts)
                touch(process_node_id, ts)
                touch(child_node_id, ts)

            # 3. OPEN HANDLING
            elif type_id == TYPE_OPEN:
                target = event.get("target", "unknown")
                fd = event.get("assigned_fd")

                if not G.has_node(process_node_id):
                    G.add_node(process_node_id, type="process", comm=comm, pid=pid)

                G.add_node(target, type="file_data")
                G.add_edge(process_node_id, target, relation="OPENS", fd=fd, timestamp=ts)
                touch(process_node_id, ts)
                touch(target, ts)

            # 4. NETWORK HANDLING 
            elif type_id == TYPE_TCP_CONNECT:
                dest_ip = event.get("dest_ip")
                dest_port = event.get("dest_port")
                network_target = f"{dest_ip}:{dest_port}"

                if not G.has_node(process_node_id):
                    G.add_node(process_node_id, type="process", comm=comm, pid=pid)

                G.add_node(network_target, type="network_socket", ip=dest_ip, port=dest_port)
                G.add_edge(process_node_id, network_target, relation="CONNECTED_TO", timestamp=ts)
                touch(process_node_id, ts)
                touch(network_target, ts)

            # 5. EXIT HANDLING
            elif type_id == TYPE_EXIT:
                if G.has_node(process_node_id):
                    G.nodes[process_node_id]["exit_code"] = event.get("exit_code")
                touch(process_node_id, ts)

            # Periodic Live Visual Refresh Layer (Every 5 seconds)
            if time.time() - last_render_time > 5.0:
                export_interactive_graph(G)
                nx.write_gexf(G, "system_behavior_graph.gexf")
                print(f"[LIVE REFRESH] Graph updated: {G.number_of_nodes()} Nodes, {G.number_of_edges()} Edges mapped.", flush=True)
                last_render_time = time.time()

            # Section 3.4.4: TTL pruning pass, checked far less often than the
            # render above — a 30-minute TTL doesn't need checking every 5s.
            if time.time() - last_prune_time > PRUNE_INTERVAL_SEC:
                prune_graph()
                last_prune_time = time.time()

        except json.JSONDecodeError:
            continue 

except KeyboardInterrupt:
    print("\nShutting down pipeline. Rendering final graph topology...")
    nx.write_gexf(G, "system_behavior_graph.gexf")
    export_interactive_graph(G)
    print("Completed. Open 'kguard_interactive_graph.html' in your browser to view your live runtime behavior!")
