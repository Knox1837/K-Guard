#!/usr/bin/env python3
"""
Live WebSocket-based graph engine for real-time security monitoring
Streams events from monitor.c to connected browser clients instantly
"""
import sys
import json
import time
from pathlib import Path
from flask import Flask, render_template_string
from flask_socketio import SocketIO, emit
import threading
import networkx as nx
from intent_validator import validate_open_event

app = Flask(__name__)
app.config['SECRET_KEY'] = 'kguard-live-monitoring'

# Production-ready SocketIO configuration
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='threading',
    ping_timeout=60,
    ping_interval=25,
    max_http_buffer_size=1e8,  # 100MB for large updates
    logger=False,
    engineio_logger=False
)

# Global graph state
G = nx.DiGraph()

# Noise Filter - expanded to reduce graph clutter
NOISE_FILTER = {
    "systemd", "systemd-journal", "dbus-daemon", "packagekitd",
    "ThreadPoolForeg", "gmain", "gdbus", "pool-",
    "threaded-ml", "pipewire", "wireplumber", "pulseaudio"
}

# Sensitive directories
SENSITIVE_DIRECTORIES = {
    "/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/sudoers.d/",
    "/etc/modules", "/etc/modprobe.d/", "/etc/init.d/", "/etc/systemd/system/",
    "/etc/cron.d/", "/etc/cron.daily/", "/etc/cron.hourly/", "/boot/",
    "/lib/modules/", "/usr/local/bin/", "/usr/local/sbin/",
    "/var/log/auth.log", "/var/log/secure", "/var/log/syslog",
    "/var/log/audit/", "/.ssh/"
}

# Event type constants
TYPE_EXEC = 1
TYPE_FORK = 2
TYPE_EXIT = 3
TYPE_OPEN = 4
TYPE_TCP_CONNECT = 5
TYPE_TCP_CLOSE = 6
TYPE_TCP_ACCEPT = 7
TYPE_DUP_REDIRECT = 8
TYPE_CREDS_CHANGE = 9
TYPE_PTRACE = 10
TYPE_MPROTECT_RWX = 11
TYPE_MEMFD_CREATE = 12
TYPE_UNLINK = 13
TYPE_RENAME = 14
TYPE_CHMOD = 15
TYPE_MODULE_LOAD = 16
TYPE_MODULE_UNLOAD = 17
TYPE_RAW_SOCKET = 18

# TTL-based pruning (10 minutes for better performance)
TTL_NS = 10 * 60 * 1_000_000_000  # 10 minutes
PRUNE_INTERVAL_SEC = 60
node_last_seen = {}
latest_event_ts = 0
last_prune_time = time.time()

# Section 3.6.3: PIDs that have raised an INTENT_VIOLATION. See the matching
# comment in graphengine.py — this is the hook point for the not-yet-built
# Kernel Deception Layer (Section 3.10); today it only drives the log line
# and node annotation below.
KDL_ACTIVE_PIDS = set()

# Stats
total_events = 0
connected_clients = 0
events_processed_per_second = 0
last_stats_time = time.time()

# Rate limiting for broadcasts
BATCH_SIZE = 50  # Batch updates for performance
BATCH_TIMEOUT = 0.1  # Send batched updates every 100ms
pending_updates = {'nodes_added': [], 'edges_added': [], 'nodes_updated': []}
last_broadcast_time = time.time()
broadcast_lock = threading.Lock()


def touch(node_id, ts):
    """Record that node_id was touched by an event at kernel time ts."""
    global latest_event_ts
    if ts is None:
        return
    node_last_seen[node_id] = ts
    if ts > latest_event_ts:
        latest_event_ts = ts


def prune_graph():
    """Remove nodes untouched for longer than TTL_NS."""
    if latest_event_ts == 0:
        return
    cutoff = latest_event_ts - TTL_NS
    stale = [n for n, ts in node_last_seen.items() if ts < cutoff]
    
    deleted_nodes = []
    for n in stale:
        if G.has_node(n):
            deleted_nodes.append(str(n))
            G.remove_node(n)
        del node_last_seen[n]
    
    if stale:
        print(f"[PRUNE] Removed {len(stale)} stale nodes", flush=True)
        # Notify clients about deleted nodes
        socketio.emit('nodes_deleted', {'nodes': deleted_nodes})


def process_event(event):
    """Process incoming event and emit updates to connected clients."""
    global total_events
    total_events += 1
    
    type_id = event.get("type_id")
    comm = event.get("comm", "unknown")
    pid = event.get("pid")
    
    # Enhanced noise filtering - filter out thread names
    if comm in NOISE_FILTER:
        return
    if "Thread-" in comm or comm.startswith("pool-"):
        return
    
    start_time = event.get("start_time_ns", 0)
    process_node_id = (pid, start_time)
    ts = event.get("timestamp_ns")
    
    nodes_to_add = []
    edges_to_add = []
    nodes_to_update = []
    
    # Helper to build node data for client
    def make_node_data(node_id, attrs):
        return {
            'id': str(node_id),
            'data': {k: (str(v) if not isinstance(v, (int, float, bool)) else v) 
                     for k, v in attrs.items()}
        }
    
    # 1. EXECUTION HANDLING
    if type_id == TYPE_EXEC:
        target = event.get("target", "unknown")
        if "/usr/lib/python3" in target:
            target = "/usr/lib/python3.14/*"
        elif "/site-packages/" in target:
            target = ".../site-packages/*"
        
        if not G.has_node(process_node_id):
            G.add_node(process_node_id, type="process", comm=comm, pid=pid, 
                      uid=event.get("uid"), gid=event.get("gid"))
            nodes_to_add.append(make_node_data(process_node_id, G.nodes[process_node_id]))
        
        if not G.has_node(target):
            G.add_node(target, type="file_binary")
            nodes_to_add.append(make_node_data(target, G.nodes[target]))
        
        G.add_edge(process_node_id, target, relation="EXECUTES", timestamp=ts)
        edges_to_add.append({
            'source': str(process_node_id),
            'target': str(target),
            'data': {'relation': 'EXECUTES', 'timestamp': ts}
        })
        touch(process_node_id, ts)
        touch(target, ts)
    
    # 2. FORK HANDLING
    elif type_id == TYPE_FORK:
        child_pid = event.get("child_pid")
        child_node_id = (child_pid, start_time)
        
        if not G.has_node(process_node_id):
            G.add_node(process_node_id, type="process", comm=comm, pid=pid)
            nodes_to_add.append(make_node_data(process_node_id, G.nodes[process_node_id]))
        
        if not G.has_node(child_node_id):
            G.add_node(child_node_id, type="process", comm=comm, pid=child_pid)
            nodes_to_add.append(make_node_data(child_node_id, G.nodes[child_node_id]))
        
        G.add_edge(process_node_id, child_node_id, relation="FORKED", timestamp=ts)
        edges_to_add.append({
            'source': str(process_node_id),
            'target': str(child_node_id),
            'data': {'relation': 'FORKED', 'timestamp': ts}
        })
        touch(process_node_id, ts)
        touch(child_node_id, ts)
    
    # 3. OPEN HANDLING
    elif type_id == TYPE_OPEN:
        target = event.get("target", "unknown")
        fd = event.get("assigned_fd")
        
        SENSITIVE_KEYWORDS = ("shadow", "passwd", "secret", "root", ".ssh", "credential")
        is_sensitive = (
            any(target.startswith(d) for d in SENSITIVE_DIRECTORIES)
            or any(kw in target for kw in SENSITIVE_KEYWORDS)
        )
        
        if is_sensitive:
            if not G.has_node(process_node_id):
                G.add_node(process_node_id, type="process", comm=comm, pid=pid)
                nodes_to_add.append(make_node_data(process_node_id, G.nodes[process_node_id]))
            
            if not G.has_node(target):
                G.add_node(target, type="file_data")
                nodes_to_add.append(make_node_data(target, G.nodes[target]))
            
            G.add_edge(process_node_id, target, relation="OPENS", fd=fd, timestamp=ts)
            edges_to_add.append({
                'source': str(process_node_id),
                'target': str(target),
                'data': {'relation': 'OPENS', 'fd': fd, 'timestamp': ts}
            })
            touch(process_node_id, ts)
            touch(target, ts)

        # Section 3.6.3: Intent-Aware validation. "intent" is None (JSON
        # null) for PIDs IntentShim never registered — those fall back to
        # the standard SENSITIVE_KEYWORDS pipeline above only, per step 1
        # of the algorithm.
        task_description = event.get("intent")
        violation = validate_open_event(pid, target, task_description)
        if violation is not None:
            if not G.has_node(process_node_id):
                G.add_node(process_node_id, type="process", comm=comm, pid=pid)
                nodes_to_add.append(make_node_data(process_node_id, G.nodes[process_node_id]))

            G.nodes[process_node_id]["security_label"] = "INTENT_VIOLATION"
            G.nodes[process_node_id]["intent_violation_path"] = violation.path
            G.nodes[process_node_id]["intent_violation_pattern"] = violation.pattern
            G.nodes[process_node_id]["intent_task_description"] = violation.task_description
            G.nodes[process_node_id]["security_score"] = (
                G.nodes[process_node_id].get("security_score", 0) + 40
            )
            KDL_ACTIVE_PIDS.add(pid)
            nodes_to_update.append(make_node_data(process_node_id, G.nodes[process_node_id]))
            touch(process_node_id, ts)
            print(
                f"[INTENT_VIOLATION] pid={pid} comm={comm!r} opened {violation.path!r} "
                f"(matched sensitive pattern {violation.pattern!r}) which is NOT justified "
                f"by its declared task: {violation.task_description!r}",
                flush=True,
            )
    
    # 4. NETWORK CONNECT HANDLING
    elif type_id == TYPE_TCP_CONNECT:
        dest_ip = event.get("dest_ip")
        dest_port = event.get("dest_port")
        network_target = f"{dest_ip}:{dest_port}"
        
        if not G.has_node(process_node_id):
            G.add_node(process_node_id, type="process", comm=comm, pid=pid)
            nodes_to_add.append(make_node_data(process_node_id, G.nodes[process_node_id]))
        
        if not G.has_node(network_target):
            G.add_node(network_target, type="network_socket", ip=dest_ip, port=dest_port)
            nodes_to_add.append(make_node_data(network_target, G.nodes[network_target]))
        
        G.add_edge(process_node_id, network_target, relation="CONNECTED_TO",
                  dest_port=dest_port, timestamp=ts)
        edges_to_add.append({
            'source': str(process_node_id),
            'target': str(network_target),
            'data': {'relation': 'CONNECTED_TO', 'dest_port': dest_port, 'timestamp': ts}
        })
        touch(process_node_id, ts)
        touch(network_target, ts)
    
    # 5. NETWORK CLOSE HANDLING
    elif type_id == TYPE_TCP_CLOSE:
        dest_ip = event.get("dest_ip")
        dest_port = event.get("dest_port")
        network_target = f"{dest_ip}:{dest_port}"
        
        if G.has_edge(process_node_id, network_target):
            G[process_node_id][network_target]["bytes_sent"] = event.get("bytes_sent", 0)
            G[process_node_id][network_target]["bytes_recv"] = event.get("bytes_recv", 0)
            G[process_node_id][network_target]["duration_ns"] = event.get("duration_ns", 0)
            nodes_to_update.append(make_node_data(process_node_id, G.nodes[process_node_id]))
        touch(process_node_id, ts)
    
    # 6-18. SECURITY EVENT HANDLING (annotate process nodes)
    elif type_id in [TYPE_DUP_REDIRECT, TYPE_TCP_ACCEPT, TYPE_CREDS_CHANGE, TYPE_PTRACE,
                     TYPE_MPROTECT_RWX, TYPE_MEMFD_CREATE, TYPE_UNLINK, TYPE_RENAME,
                     TYPE_CHMOD, TYPE_MODULE_LOAD, TYPE_MODULE_UNLOAD, TYPE_RAW_SOCKET]:
        
        if not G.has_node(process_node_id):
            G.add_node(process_node_id, type="process", comm=comm, pid=pid)
            nodes_to_add.append(make_node_data(process_node_id, G.nodes[process_node_id]))
        
        # Update security attributes based on event type
        if type_id == TYPE_DUP_REDIRECT:
            G.nodes[process_node_id]["has_fd_redirect"] = True
            G.nodes[process_node_id]["security_label"] = "CRITICAL_REVERSE_SHELL_FD_REDIRECT"
            G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 50
        
        elif type_id == TYPE_TCP_ACCEPT:
            G.nodes[process_node_id]["inbound_connections"] = G.nodes[process_node_id].get("inbound_connections", 0) + 1
        
        elif type_id == TYPE_CREDS_CHANGE:
            old_uid = event.get("old_uid", 0)
            new_uid = event.get("new_uid", 0)
            G.nodes[process_node_id]["creds_change_count"] = G.nodes[process_node_id].get("creds_change_count", 0) + 1
            if new_uid == 0 and old_uid != 0:
                G.nodes[process_node_id]["escalated_to_root"] = True
                G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 30
        
        elif type_id == TYPE_PTRACE:
            G.nodes[process_node_id]["ptrace_count"] = G.nodes[process_node_id].get("ptrace_count", 0) + 1
            G.nodes[process_node_id]["has_ptrace"] = True
            G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 15
        
        elif type_id == TYPE_MPROTECT_RWX:
            G.nodes[process_node_id]["mprotect_rwx_count"] = G.nodes[process_node_id].get("mprotect_rwx_count", 0) + 1
            G.nodes[process_node_id]["has_rwx_mprotect"] = True
            G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 20
        
        elif type_id == TYPE_MEMFD_CREATE:
            G.nodes[process_node_id]["memfd_count"] = G.nodes[process_node_id].get("memfd_count", 0) + 1
            G.nodes[process_node_id]["has_memfd_create"] = True
            G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 25
        
        elif type_id == TYPE_UNLINK:
            G.nodes[process_node_id]["unlink_count"] = G.nodes[process_node_id].get("unlink_count", 0) + 1
            G.nodes[process_node_id]["has_file_deletion"] = True
            G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 3
        
        elif type_id == TYPE_RENAME:
            G.nodes[process_node_id]["rename_count"] = G.nodes[process_node_id].get("rename_count", 0) + 1
            G.nodes[process_node_id]["has_file_rename"] = True
            G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 5
        
        elif type_id == TYPE_CHMOD:
            mode = event.get("mode", 0)
            G.nodes[process_node_id]["chmod_count"] = G.nodes[process_node_id].get("chmod_count", 0) + 1
            G.nodes[process_node_id]["has_chmod"] = True
            if mode & 0o4000:
                G.nodes[process_node_id]["has_setuid_chmod"] = True
                G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 20
            else:
                G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 3
        
        elif type_id == TYPE_MODULE_LOAD:
            G.nodes[process_node_id]["module_load_count"] = G.nodes[process_node_id].get("module_load_count", 0) + 1
            G.nodes[process_node_id]["has_module_load"] = True
            G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 35
        
        elif type_id == TYPE_MODULE_UNLOAD:
            G.nodes[process_node_id]["module_unload_count"] = G.nodes[process_node_id].get("module_unload_count", 0) + 1
            G.nodes[process_node_id]["has_module_unload"] = True
            G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 15
        
        elif type_id == TYPE_RAW_SOCKET:
            G.nodes[process_node_id]["raw_socket_count"] = G.nodes[process_node_id].get("raw_socket_count", 0) + 1
            G.nodes[process_node_id]["has_raw_socket"] = True
            G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 25
        
        nodes_to_update.append(make_node_data(process_node_id, G.nodes[process_node_id]))
        touch(process_node_id, ts)
    
    # 19. EXIT HANDLING
    elif type_id == TYPE_EXIT:
        if G.has_node(process_node_id):
            G.nodes[process_node_id]["status"] = "terminated"
            G.nodes[process_node_id]["exit_code"] = event.get("exit_code")
            G.nodes[process_node_id]["exit_time"] = ts
            nodes_to_update.append(make_node_data(process_node_id, G.nodes[process_node_id]))
        touch(process_node_id, ts)
    
    # Batch updates for performance
    if nodes_to_add or edges_to_add or nodes_to_update:
        with broadcast_lock:
            pending_updates['nodes_added'].extend(nodes_to_add)
            pending_updates['edges_added'].extend(edges_to_add)
            pending_updates['nodes_updated'].extend(nodes_to_update)
        
        # Broadcast if batch is full or timeout reached
        flush_pending_updates(force=False)


def flush_pending_updates(force=False):
    """Flush batched updates to clients."""
    global last_broadcast_time
    
    with broadcast_lock:
        current_time = time.time()
        time_elapsed = current_time - last_broadcast_time
        
        total_pending = (len(pending_updates['nodes_added']) + 
                        len(pending_updates['edges_added']) + 
                        len(pending_updates['nodes_updated']))
        
        should_flush = (force or 
                       total_pending >= BATCH_SIZE or 
                       time_elapsed >= BATCH_TIMEOUT)
        
        if should_flush and total_pending > 0:
            socketio.emit('graph_update', {
                'nodes_added': pending_updates['nodes_added'][:],
                'edges_added': pending_updates['edges_added'][:],
                'nodes_updated': pending_updates['nodes_updated'][:],
                'stats': {
                    'total_nodes': G.number_of_nodes(),
                    'total_edges': G.number_of_edges(),
                    'total_events': total_events,
                    'events_per_sec': events_processed_per_second
                }
            })
            
            # Clear pending updates
            pending_updates['nodes_added'].clear()
            pending_updates['edges_added'].clear()
            pending_updates['nodes_updated'].clear()
            last_broadcast_time = current_time


def stdin_reader():
    """Read events from stdin and process them."""
    print("[LIVE ENGINE] Reading events from stdin...", flush=True)
    global last_prune_time, events_processed_per_second, last_stats_time
    
    event_counter = 0
    
    for line in sys.stdin:
        try:
            event = json.loads(line.strip())
            process_event(event)
            event_counter += 1
            
            # Calculate events per second
            current_time = time.time()
            if current_time - last_stats_time >= 1.0:
                events_processed_per_second = event_counter
                event_counter = 0
                last_stats_time = current_time
            
            # Periodic pruning
            if current_time - last_prune_time > PRUNE_INTERVAL_SEC:
                prune_graph()
                last_prune_time = current_time
                flush_pending_updates(force=True)
                
        except json.JSONDecodeError:
            continue
        except Exception as e:
            print(f"[ERROR] Processing event: {e}", flush=True)
            import traceback
            traceback.print_exc()


@socketio.on('connect')
def handle_connect():
    global connected_clients
    connected_clients += 1
    print(f"[CLIENT] Connected (total: {connected_clients})", flush=True)
    
    try:
        # Send current graph state to new client
        nodes = [{'id': str(n), 'data': {k: (str(v) if not isinstance(v, (int, float, bool)) else v) 
                                          for k, v in attrs.items()}} 
                 for n, attrs in G.nodes(data=True)]
        edges = [{'source': str(s), 'target': str(t), 'data': attrs} 
                 for s, t, attrs in G.edges(data=True)]
        
        # Send in chunks if too large
        if len(nodes) > 1000:
            print(f"[CLIENT] Sending large state ({len(nodes)} nodes) in chunks", flush=True)
            chunk_size = 500
            for i in range(0, len(nodes), chunk_size):
                emit('initial_state_chunk', {
                    'nodes': nodes[i:i+chunk_size],
                    'edges': edges[i:i+chunk_size] if i < len(edges) else [],
                    'chunk': i // chunk_size,
                    'is_last': i + chunk_size >= len(nodes)
                })
        else:
            emit('initial_state', {
                'nodes': nodes,
                'edges': edges,
                'stats': {
                    'total_nodes': G.number_of_nodes(),
                    'total_edges': G.number_of_edges(),
                    'total_events': total_events,
                    'events_per_sec': events_processed_per_second
                }
            })
    except Exception as e:
        print(f"[ERROR] Failed to send initial state: {e}", flush=True)
        emit('error', {'message': 'Failed to load graph state'})


@socketio.on('disconnect')
def handle_disconnect():
    global connected_clients
    connected_clients -= 1
    print(f"[CLIENT] Disconnected (total: {connected_clients})", flush=True)


@app.route('/')
def index():
    """Serve the live dashboard HTML."""
    return render_template_string(open('templates/live_dashboard.html').read())


def periodic_flush():
    """Periodically flush pending updates to avoid stale data."""
    while True:
        time.sleep(BATCH_TIMEOUT)
        flush_pending_updates(force=True)


if __name__ == '__main__':
    # Start stdin reader in background thread
    reader_thread = threading.Thread(target=stdin_reader, daemon=True)
    reader_thread.start()
    
    # Start periodic flush thread
    flush_thread = threading.Thread(target=periodic_flush, daemon=True)
    flush_thread.start()
    
    print("[LIVE ENGINE] Starting WebSocket server on http://localhost:5000", flush=True)
    print("[LIVE ENGINE] Open http://localhost:5000 in your browser for live monitoring", flush=True)
    print("[LIVE ENGINE] Batching updates every 100ms or 50 events", flush=True)
    
    # Start Flask-SocketIO server
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
