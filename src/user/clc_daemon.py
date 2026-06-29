#!/usr/bin/env python3
import os
import time
import errno
import json
import subprocess
import networkx as nx
import psutil 

def get_proc_pids():
    """Enumerates all active PIDs currently visible in the /proc filesystem."""
    try:
        return set(int(d) for d in os.listdir('/proc') if d.isdigit())
    except Exception:
        return set()

def fetch_ebpf_kernel_pids():
    """
    Queries the live kernel space map 'active_kernel_pids' via bpftool.
    Returns a dictionary mapping PID (int) -> Kernel Timestamp (int).
    """
    kernel_pids = {}
    try:
        # Dump the map contents in JSON format using bpftool
        raw_dump = subprocess.check_output(
            "sudo bpftool map dump name active_kernel_p", 
            shell=True, 
            stderr=subprocess.DEVNULL
        ).decode()
        
        if not raw_dump.strip():
            return kernel_pids
            
        parsed_data = json.loads(raw_dump)
        
        # Parse through the bpftool JSON representation
        for item in parsed_data:
            # bpftool returns keys and values as hex strings or sub-elements
            raw_key = item.get("key")
            raw_val = item.get("value")
            
            if raw_key is not None and raw_val is not None:
                # Convert hex string or integer formats safely
                pid = int(raw_key, 16) if isinstance(raw_key, str) else int(raw_key)
                timestamp = int(raw_val, 16) if isinstance(raw_val, str) else int(raw_val)
                kernel_pids[pid] = timestamp
    except Exception:
        # Returns empty if map isn't loaded yet or if bpftool fails
        pass
    return kernel_pids

def verify_hidden_pid(pid, initial_kernel_pids):
    """
    Section 3.5.3 Race Condition Mitigation Protocol:
    Differentiates true rootkit hiding tactics from normal Linux sub-threads and leaks.
    """
    # 1. Grace window for high-concurrency loops
    time.sleep(0.5)

    # 2. Check if it's still tracked by the kernel map
    current_kernel_pids = fetch_ebpf_kernel_pids()
    if pid not in current_kernel_pids:
        return "CLEARED_RACE"

    # 3. Handle thread-group validation
    # Check if this PID is actually a sub-thread of an active process
    is_sub_thread = False
    try:
        # Check if the ID is tracked anywhere within active process thread charts
        for p in psutil.process_iter(['pid']):
            try:
                # Scan the task IDs of the process
                if pid in [t.id for t in p.threads()]:
                    is_sub_thread = True
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass

    if is_sub_thread:
        # It's a normal thread. It doesn't get a /proc/<pid> folder, 
        # but it shouldn't leak in the map forever once it stops.
        return "STUCK_MAP_ENTRY"

    # 4. Standard validation loop for normal monolithic tasks
    is_alive = False
    is_zombie = False
    try:
        proc = psutil.Process(pid)
        if proc.status() == psutil.STATUS_ZOMBIE:
            is_zombie = True
        else:
            is_alive = True
    except psutil.NoSuchProcess:
        is_alive = False
    except psutil.AccessDenied:
        is_alive = True

    visible_in_proc = pid in get_proc_pids()

    # CRITICAL VERDICT:
    if is_alive and not is_zombie and not visible_in_proc:
        return "ROOTKIT" 
        
    if is_zombie or (not is_alive and not visible_in_proc):
        return "STUCK_MAP_ENTRY"
        
    return "CLEARED_RACE"

def run_cross_layer_consistency_check():
    """Live daemon monitoring engine comparing eBPF kernel state against /proc scans."""
    print("[K-GUARD] CLC DAEMON: Cross-Layer Consistency Check Engine initialized.")
    print("Continuous Monitoring Target: 'active_kernel_pids' eBPF Map.")
    
    # Ensure bpftool is available on the host system
    try:
        subprocess.check_output("which bpftool", shell=True)
    except subprocess.CalledProcessError:
        print("Error: 'bpftool' utility is missing. Install it using: sudo apt install linux-tools-common")
        return

    # Keep track of previously loaded graph to append alert attributes if it exists
    gexf_path = "system_behavior_graph.gexf"

    while True:
        try:
            # 1. Fetch live user-space view
            proc_pids = get_proc_pids()

            # 2. Fetch live kernel-space ground-truth view
            kernel_pids_dict = fetch_ebpf_kernel_pids()
            kernel_pids = set(kernel_pids_dict.keys())

            # If the map is empty, monitor might not be running or no forks occurred yet
            if not kernel_pids:
                time.sleep(2.5)
                continue

            # 3. Compute Set Discrepancy (Present in Kernel eBPF, but invisible to /proc)
            candidate_hidden_pids = kernel_pids - proc_pids

            for pid in candidate_hidden_pids:
                # Mitigate race conditions and map leaks before alerting
                status = verify_hidden_pid(pid, kernel_pids_dict)
                
                if status == "ROOTKIT":
                    print(f"[CRITICAL ALERT] CLC DETECTED HIDDEN PROCESS: PID {pid}!")
                    print(f"   -> This process occupies active slots in eBPF scheduler tracking maps.")
                    print(f"   -> The PID has been actively stripped from the user-space /proc file tree.")
                    print(f"   -> Verdict: Verified Kernel Rootkit/Evasive Malware Activity.\n")
                    
                    # 4. Inject this anomaly state straight into the shared provenance layout
                    if os.path.exists(gexf_path):
                        try:
                            G = nx.read_gexf(gexf_path)
                            proc_node_id = f"proc_{pid}"
                            
                            if G.has_node(proc_node_id):
                                G.nodes[proc_node_id]["status"] = "ROOTKIT_HIDDEN"
                                G.nodes[proc_node_id]["color"] = "#FF0000" # Force node to bright red
                                nx.write_gexf(G, gexf_path)
                        except Exception:
                            pass # Avoid file lock crash if graphengine is writing to it

                elif status == "STUCK_MAP_ENTRY":
                    # Convert the base-10 PID into 4 exact little-endian bytes
                    # This ensures it maps cleanly to a u32 key inside the eBPF map
                    pid_bytes = pid.to_bytes(4, byteorder='little')
                    hex_bytes_str = " ".join(f"0x{b:02x}" for b in pid_bytes)
                    
                    print(f"🧹 [MEM_CLEANUP] Purging orphaned PID {pid} (Bytes: {hex_bytes_str}) from eBPF map...")
                    
                    # Pass the explicit 4-byte key array directly to the kernel
                    subprocess.run(
                        f"sudo bpftool map delete name active_kernel_p key {hex_bytes_str}", 
                        shell=True, 
                        stderr=subprocess.DEVNULL
                    )

            # Check consistency every 2.5 seconds as planned
            time.sleep(2.5)

        except KeyboardInterrupt:
            print("\nStopping Cross-Layer Consistency monitoring cleanly.")
            break
        except Exception as e:
            print(f"[CLC ERROR] Loop Exception: {e}")
            time.sleep(2.5)

if __name__ == "__main__":
    # Check for root permissions required to interface with bpftool maps
    if os.getuid() != 0:
        print("❌ Error: This daemon requires root privileges to read eBPF structures.")
        print("   Please run using: sudo python3 src/user/clc_daemon.py")
        exit(1)
        
    run_cross_layer_consistency_check()
