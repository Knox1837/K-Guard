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
                
                SENSITIVE_KEYWORDS = ("shadow", "passwd", "secret", "root", ".ssh", "credential")
                is_sensitive = (
                    any(target.startswith(d) for d in SENSITIVE_DIRECTORIES)
                    or any(kw in target for kw in SENSITIVE_KEYWORDS)
                )
                
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
                G.add_edge(process_node_id, network_target, relation="CONNECTED_TO",
                           dest_port=dest_port, timestamp=ts)
                touch(process_node_id, ts)
                touch(network_target, ts)

            # NETWORK CLOSE HANDLING 
            elif type_id == TYPE_TCP_CLOSE:
                dest_ip = event.get("dest_ip")
                dest_port = event.get("dest_port")
                network_target = f"{dest_ip}:{dest_port}"

                if G.has_edge(process_node_id, network_target):
                    G[process_node_id][network_target]["bytes_sent"] = event.get("bytes_sent", 0)
                    G[process_node_id][network_target]["bytes_recv"] = event.get("bytes_recv", 0)
                    G[process_node_id][network_target]["duration_ns"] = event.get("duration_ns", 0)
                touch(process_node_id, ts)
            
            # REVERSE SHELL HANDLING
            elif type_id == TYPE_DUP_REDIRECT:
                if pid is None:		# skip if this event carries no identity
                    continue
                if not G.has_node(process_node_id):
                    G.add_node(process_node_id, type="process", comm=comm, pid=pid)
                G.nodes[process_node_id]["security_label"] = "CRITICAL_REVERSE_SHELL_FD_REDIRECT"
                G.nodes[process_node_id]["redirected_fd"] = event.get("redirected_fd", "")   # which stdio fd (0/1/2)
                G.nodes[process_node_id]["socket_fd"] = event.get("socket_fd", "")           # which fd held the socket
                G.nodes[process_node_id]["has_fd_redirect"] = True
                G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 50
                touch(process_node_id, ts)
            
            # 6. TCP ACCEPT (INBOUND CONNECTION) HANDLING
            elif type_id == TYPE_TCP_ACCEPT:
                src_ip = event.get("src_ip")
                src_port = event.get("src_port")
                remote_ip = event.get("remote_ip")
                remote_port = event.get("remote_port")
                
                if not G.has_node(process_node_id):
                    G.add_node(process_node_id, type="process", comm=comm, pid=pid)
                
                # Track inbound connections as node attribute
                G.nodes[process_node_id]["inbound_connections"] = G.nodes[process_node_id].get("inbound_connections", 0) + 1
                G.nodes[process_node_id]["last_inbound_from"] = f"{remote_ip}:{remote_port}"
                touch(process_node_id, ts)
            
            # 7. CREDENTIAL CHANGE HANDLING (PRIVILEGE ESCALATION)
            elif type_id == TYPE_CREDS_CHANGE:
                old_uid = event.get("old_uid", 0)
                new_uid = event.get("new_uid", 0)
                
                if not G.has_node(process_node_id):
                    G.add_node(process_node_id, type="process", comm=comm, pid=pid)
                
                G.nodes[process_node_id]["creds_change_count"] = G.nodes[process_node_id].get("creds_change_count", 0) + 1
                G.nodes[process_node_id]["last_uid_change"] = f"{old_uid}->{new_uid}"
                
                # Flag privilege escalation to root
                if new_uid == 0 and old_uid != 0:
                    G.nodes[process_node_id]["escalated_to_root"] = True
                    G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 30
                    if not G.nodes[process_node_id].get("security_label"):
                        G.nodes[process_node_id]["security_label"] = "PRIVILEGE_ESCALATION"
                
                touch(process_node_id, ts)
            
            # 8. PTRACE HANDLING (PROCESS INJECTION / DEBUGGING)
            elif type_id == TYPE_PTRACE:
                request = event.get("request", 0)
                target_pid = event.get("target_pid", 0)
                
                if not G.has_node(process_node_id):
                    G.add_node(process_node_id, type="process", comm=comm, pid=pid)
                
                G.nodes[process_node_id]["ptrace_count"] = G.nodes[process_node_id].get("ptrace_count", 0) + 1
                G.nodes[process_node_id]["has_ptrace"] = True
                G.nodes[process_node_id]["last_ptrace_target"] = target_pid
                G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 15
                touch(process_node_id, ts)
            
            # 9. MPROTECT RWX HANDLING (SHELLCODE PATTERN)
            elif type_id == TYPE_MPROTECT_RWX:
                addr = event.get("addr", 0)
                prot = event.get("prot", 0)
                
                if not G.has_node(process_node_id):
                    G.add_node(process_node_id, type="process", comm=comm, pid=pid)
                
                G.nodes[process_node_id]["mprotect_rwx_count"] = G.nodes[process_node_id].get("mprotect_rwx_count", 0) + 1
                G.nodes[process_node_id]["has_rwx_mprotect"] = True
                G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 20
                touch(process_node_id, ts)
            
            # 10. MEMFD_CREATE HANDLING (FILELESS EXECUTION)
            elif type_id == TYPE_MEMFD_CREATE:
                memfd_name = event.get("name", "")
                flags = event.get("flags", 0)
                
                if not G.has_node(process_node_id):
                    G.add_node(process_node_id, type="process", comm=comm, pid=pid)
                
                G.nodes[process_node_id]["memfd_count"] = G.nodes[process_node_id].get("memfd_count", 0) + 1
                G.nodes[process_node_id]["has_memfd_create"] = True
                G.nodes[process_node_id]["last_memfd_name"] = memfd_name
                G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 25
                touch(process_node_id, ts)
            
            # 11. UNLINK HANDLING (FILE DELETION / ANTI-FORENSICS)
            elif type_id == TYPE_UNLINK:
                target = event.get("target", "")
                
                if not G.has_node(process_node_id):
                    G.add_node(process_node_id, type="process", comm=comm, pid=pid)
                
                G.nodes[process_node_id]["unlink_count"] = G.nodes[process_node_id].get("unlink_count", 0) + 1
                G.nodes[process_node_id]["has_file_deletion"] = True
                
                # Higher score for deleting sensitive files
                if any(kw in target for kw in ["log", "history", "auth", ".bash"]):
                    G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 10
                else:
                    G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 3
                
                touch(process_node_id, ts)
            
            # 12. RENAME HANDLING (FILE MASQUERADING)
            elif type_id == TYPE_RENAME:
                old_path = event.get("old_path", "")
                new_path = event.get("new_path", "")
                
                if not G.has_node(process_node_id):
                    G.add_node(process_node_id, type="process", comm=comm, pid=pid)
                
                G.nodes[process_node_id]["rename_count"] = G.nodes[process_node_id].get("rename_count", 0) + 1
                G.nodes[process_node_id]["has_file_rename"] = True
                G.nodes[process_node_id]["last_rename"] = f"{old_path}->{new_path}"
                G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 5
                touch(process_node_id, ts)
            
            # 13. CHMOD HANDLING (PERMISSION TAMPERING / SETUID BACKDOORS)
            elif type_id == TYPE_CHMOD:
                target = event.get("target", "")
                mode = event.get("mode", 0)
                
                if not G.has_node(process_node_id):
                    G.add_node(process_node_id, type="process", comm=comm, pid=pid)
                
                G.nodes[process_node_id]["chmod_count"] = G.nodes[process_node_id].get("chmod_count", 0) + 1
                G.nodes[process_node_id]["has_chmod"] = True
                
                # Check for setuid bit (0o4000)
                if mode & 0o4000:
                    G.nodes[process_node_id]["has_setuid_chmod"] = True
                    G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 20
                else:
                    G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 3
                
                touch(process_node_id, ts)
            
            # 14. MODULE LOAD HANDLING (ROOTKIT TERRITORY)
            elif type_id == TYPE_MODULE_LOAD:
                module = event.get("module", "")
                
                if not G.has_node(process_node_id):
                    G.add_node(process_node_id, type="process", comm=comm, pid=pid)
                
                G.nodes[process_node_id]["module_load_count"] = G.nodes[process_node_id].get("module_load_count", 0) + 1
                G.nodes[process_node_id]["has_module_load"] = True
                G.nodes[process_node_id]["last_module_loaded"] = module
                G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 35
                touch(process_node_id, ts)
            
            # 15. MODULE UNLOAD HANDLING
            elif type_id == TYPE_MODULE_UNLOAD:
                module_name = event.get("module_name", "")
                
                if not G.has_node(process_node_id):
                    G.add_node(process_node_id, type="process", comm=comm, pid=pid)
                
                G.nodes[process_node_id]["module_unload_count"] = G.nodes[process_node_id].get("module_unload_count", 0) + 1
                G.nodes[process_node_id]["has_module_unload"] = True
                G.nodes[process_node_id]["last_module_unloaded"] = module_name
                G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 15
                touch(process_node_id, ts)
            
            # 16. RAW SOCKET HANDLING (PACKET SNIFFING / CRAFTING)
            elif type_id == TYPE_RAW_SOCKET:
                family = event.get("family", 0)
                protocol = event.get("protocol", 0)
                
                if not G.has_node(process_node_id):
                    G.add_node(process_node_id, type="process", comm=comm, pid=pid)
                
                G.nodes[process_node_id]["raw_socket_count"] = G.nodes[process_node_id].get("raw_socket_count", 0) + 1
                G.nodes[process_node_id]["has_raw_socket"] = True
                G.nodes[process_node_id]["raw_socket_family"] = family
                G.nodes[process_node_id]["raw_socket_protocol"] = protocol
                G.nodes[process_node_id]["security_score"] = G.nodes[process_node_id].get("security_score", 0) + 25
                touch(process_node_id, ts)
                                
 
            # 17. EXIT HANDLING
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
