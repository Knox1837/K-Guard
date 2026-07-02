import sys
import json
import time
from pathlib import Path

import networkx as nx
from pyvis.network import Network
from graph import NODE_COUNT_HISTORY_FILE, export_interactive_graph

BASE_DIR = Path(__file__).resolve().parents[2]
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
GEXF_FILE = OUTPUT_DIR / "system_behavior_graph.gexf"

# Initialize Directed Causal Provenance Graph
G = nx.DiGraph()

# Noise Filter
NOISE_FILTER = {"systemd", "systemd-journal", "dbus-daemon", "packagekitd"}

# Sensitive directories and files that should always trigger graph nodes
SENSITIVE_DIRECTORIES = {
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/sudoers.d/",
    "/etc/modules",
    "/etc/modprobe.d/",
    "/etc/init.d/",
    "/etc/systemd/system/",
    "/etc/cron.d/",
    "/etc/cron.daily/",
    "/etc/cron.hourly/",
    "/boot/",
    "/lib/modules/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/syslog",
    "/var/log/audit/",
    "/.ssh/" 
}

TYPE_EXEC = 1
TYPE_FORK = 2
TYPE_EXIT = 3
TYPE_OPEN = 4
TYPE_TCP_CONNECT = 5

last_render_time = time.time()
node_count_history = []

# Section 3.4.4 Memory Management: TTL-based pruning 
TTL_NS = 30 * 60 * 1_000_000_000   # 30 minutes, matches Section 3.4.4 default
PRUNE_INTERVAL_SEC = 60            # how often (real seconds) we run a prune pass

node_last_seen = {}      # node_id -> latest timestamp_ns that touched it
latest_event_ts = 0      # the newest timestamp_ns observed from any event so far
last_prune_time = time.time()

def touch(node_id, ts):
    """Record that `node_id` was touched by an event at kernel time `ts`."""
    global latest_event_ts
    
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
                
                is_sensitive = any(target.startswith(d) for d in SENSITIVE_DIRECTORIES)
                
                if is_sensitive:
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
                    G.nodes[process_node_id]["status"] = "terminated"
                    G.nodes[process_node_id]["exit_code"] = event.get("exit_code")
                    G.nodes[process_node_id]["exit_time"] = ts # Keep track of when it died
                touch(process_node_id, ts)

            # Periodic Live Visual Refresh Layer (Every 5 seconds)
            if time.time() - last_render_time > 5.0:
                history_point = {
                    "label": time.strftime("%H:%M:%S", time.localtime()),
                    "count": G.number_of_nodes(),
                }
                node_count_history.append(history_point)
                with open(NODE_COUNT_HISTORY_FILE, "w", encoding="utf-8") as history_file:
                    json.dump(node_count_history, history_file)

                export_interactive_graph(G, node_count_history=node_count_history)
                nx.write_gexf(G, str(GEXF_FILE))
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
    nx.write_gexf(G, str(GEXF_FILE))
    export_interactive_graph(G, node_count_history=node_count_history)
    print(f"Completed. Open '{OUTPUT_DIR / 'kguard_interactive_graph.html'}' in your browser to view your live runtime behavior!")
