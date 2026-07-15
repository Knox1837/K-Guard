import html
import json
from pathlib import Path

import networkx as nx
from pyvis.network import Network
import igraph as ig

BASE_DIR = Path(__file__).resolve().parents[2]
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

NODE_COUNT_HISTORY_FILE = OUTPUT_DIR / "node_count_history.json"

def export_interactive_graph(
    graph_obj_orignal,
    filter_pid=None,
    filter_name=None,
    html_path=OUTPUT_DIR / "kguard_interactive_graph.html",
    node_count_history=None,
):
    """Transforms our composite NetworkX graph into an interactive browser deployment."""
    pid_filter_applied = False
    if filter_pid is not None:
        print(f"[INFO] Rendering subgraph for PID: {filter_pid}")
        graph_to_render = filter_by_pid(graph_obj_orignal, int(filter_pid))
        pid_filter_applied = True
        if not graph_to_render:
            pid_filter_applied = False
            print(f"[WARN] No subgraph found for PID: {filter_pid}. Rendering the full graph instead.")
            graph_to_render = graph_obj_orignal
    else:
        graph_to_render = graph_obj_orignal
    
    if not pid_filter_applied and filter_name:
        print(f"[INFO] Rendering subgraph for process name: {filter_name}")
        # Filter nodes by process name
        graph_to_render = filter_by_name(graph_obj_orignal, filter_name)
        if not graph_to_render:
            print(f"[WARN] No subgraph found for process name: {filter_name}. Rendering the full graph instead.")
            graph_to_render = graph_obj_orignal

    graph_obj = graph_to_render
    g_ig = ig.Graph.from_networkx(graph_obj)    

    if len(g_ig.vs) > 200:
        print(f"[INFO] Graph has {len(g_ig.vs)} size exceeding 200, Filtering by degree.")
        top_indices = sorted(range(len(g_ig.vs)), key=lambda i: g_ig.degree(i), reverse=True)[:200]
        g_ig = g_ig.subgraph(top_indices)
        graph_obj = g_ig.to_networkx()

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

    if node_count_history is None and filter_pid is None and not filter_name:
        node_count_history = _load_node_count_history(NODE_COUNT_HISTORY_FILE)

    if not node_count_history:
        node_count_history = [{"label": "now", "count": graph_obj.number_of_nodes()}]

    telemetry_script = _build_node_count_chart_html(node_count_history)

    # Save out as an interactive standalone web application webpage layout
    html_path = Path(html_path)
    html_path.parent.mkdir(parents=True, exist_ok=True)
    net.save_graph(str(html_path))
    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()
    
    if "</body>" in html:
            html = html.replace("</body>", telemetry_script + "</body>")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html)
    

    freeze_physics_after_stabilization(html_path)

def freeze_physics_after_stabilization(html_path):
    """Patch the saved HTML so physics stops once the layout settles."""
    try:
        html_path = Path(html_path)
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


def _load_node_count_history(history_path):
    try:
        with open(history_path, "r", encoding="utf-8") as history_file:
            history = json.load(history_file)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []

    if not isinstance(history, list):
        return []

    cleaned_history = []
    for point in history:
        if not isinstance(point, dict):
            continue
        label = str(point.get("label", ""))
        try:
            count = int(point.get("count", 0))
        except (TypeError, ValueError):
            continue
        cleaned_history.append({"label": label, "count": count})
    return cleaned_history


def _build_node_count_chart_html(history_points):
    labels = [html.escape(str(point.get("label", ""))) for point in history_points]
    counts = []
    for point in history_points:
        try:
            counts.append(int(point.get("count", 0)))
        except (TypeError, ValueError):
            counts.append(0)

    width = 420
    height = 220
    margin_left = 48
    margin_right = 18
    margin_top = 18
    margin_bottom = 42

    plot_width = width - margin_left - margin_right
    plot_height = height - margin_top - margin_bottom
    min_count = min(counts)
    max_count = max(counts)
    if min_count == max_count:
        max_count += 1

    def x_for_index(index):
        if len(counts) == 1:
            return margin_left + plot_width / 2
        return margin_left + (index * plot_width / (len(counts) - 1))

    def y_for_count(count):
        normalized = (count - min_count) / (max_count - min_count)
        return margin_top + (plot_height - normalized * plot_height)

    points = []
    circles = []
    tick_labels = []
    for index, count in enumerate(counts):
        x = x_for_index(index)
        y = y_for_count(count)
        points.append(f"{x:.2f},{y:.2f}")
        circles.append(
            f'<circle cx="{x:.2f}" cy="{y:.2f}" r="3.5" fill="#58a6ff" />'
        )

    tick_indexes = sorted({0, len(counts) // 2, len(counts) - 1})
    for index in tick_indexes:
        x = x_for_index(index)
        tick_labels.append(
            f'<text x="{x:.2f}" y="{height - 14}" fill="#c9d1d9" font-size="10" text-anchor="middle">{labels[index]}</text>'
        )

    y_ticks = []
    for value in [min_count, (min_count + max_count) // 2, max_count]:
        y = y_for_count(value)
        y_ticks.append(
            f'<text x="{margin_left - 10}" y="{y + 3:.2f}" fill="#c9d1d9" font-size="10" text-anchor="end">{value}</text>'
        )

    return f"""
    <div id="chart-container" style="position: absolute; bottom: 20px; left: 20px; width: 420px; background: #161b22; border: 1px solid #30363d; padding: 10px; border-radius: 8px; box-shadow: 0 8px 24px rgba(0, 0, 0, 0.25);">
        <div style="color: #f0f6fc; font-size: 13px; font-weight: 600; margin-bottom: 8px;">Nodes vs Time</div>
        <svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Nodes versus time chart">
            <rect x="0" y="0" width="{width}" height="{height}" rx="6" fill="#0d1117" stroke="#30363d" />
            <line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" y2="{height - margin_bottom}" stroke="#30363d" />
            <line x1="{margin_left}" y1="{height - margin_bottom}" x2="{width - margin_right}" y2="{height - margin_bottom}" stroke="#30363d" />
            <polyline fill="none" stroke="#58a6ff" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round" points="{' '.join(points)}" />
            {''.join(circles)}
            {''.join(tick_labels)}
            {''.join(y_ticks)}
        </svg>
    </div>
    """

def filter_by_pid(graph, target_pid):
    # 1. Sanitize: Create a copy containing ONLY hashable nodes (str, int, tuple)
    # This removes any accidental 'dict' nodes that are causing the crash
    valid_nodes = [n for n in graph.nodes() if isinstance(n, (str, int, tuple))]
    clean_graph = graph.subgraph(valid_nodes).copy()
    
    # 2. Find target nodes using the cleaned graph
    target_nodes = []
    for n in clean_graph.nodes(data=True):
        # Safely check PID, converting to string to avoid type mismatches
        if str(n[1].get("pid")) == str(target_pid):
            target_nodes.append(n[0]) # Add the node identifier, not the full tuple

    if not target_nodes:
        print(f"[WARN] No nodes found for PID: {target_pid}")
        return None
    
    # 3. Traversal: Now safe to run because clean_graph has no dictionaries
    subgraph_nodes = set()
    for start_node in target_nodes:
        subgraph_nodes.update(nx.ancestors(clean_graph, start_node))
        subgraph_nodes.update(nx.descendants(clean_graph, start_node))
        subgraph_nodes.add(start_node)
    
    return clean_graph.subgraph(subgraph_nodes)

def filter_by_name(graph, target_name):
    # 1. Sanitize: Create a copy containing ONLY hashable nodes (str, int, tuple)
    valid_nodes = [n for n in graph.nodes() if isinstance(n, (str, int, tuple))]
    clean_graph = graph.subgraph(valid_nodes).copy()
    
    # 2. Find target nodes using the cleaned graph
    target_nodes = []
    for n in clean_graph.nodes(data=True):
        if target_name in str(n[1].get("comm", "")):
            target_nodes.append(n[0]) # Add the node identifier

    if not target_nodes:
        print(f"[WARN] No nodes found for process name: {target_name}")
        return None
    
    # 3. Traversal: Now safe to run because clean_graph has no dictionaries
    subgraph_nodes = set()
    for start_node in target_nodes:
        subgraph_nodes.update(nx.ancestors(clean_graph, start_node))
        subgraph_nodes.update(nx.descendants(clean_graph, start_node))
        subgraph_nodes.add(start_node)
    
    return clean_graph.subgraph(subgraph_nodes)

from networkx import read_gexf
#graph = read_gexf("output/system_behavior_graph.gexf")
#export_interactive_graph(graph, html_path="test.html")
#for n in graph.nodes(data=True):
#    print(f"Node: {n[0]}, Attributes: {n[1].get('pid')}")