#!/usr/bin/env python3
"""
test_clc_daemon.py
--------------------
Validates clc_daemon.py's verify_hidden_pid() / ROOTKIT verdict path using
a REAL forked process and the REAL eBPF map, with a controlled gap injected
only into this test process's own view of /proc.

Why monkeypatch instead of anything filesystem/kernel level:
  - fetch_ebpf_kernel_pids() is untouched -> real bpftool dump, real map.
  - The spawned child is a real process -> sched_process_fork genuinely
    populates active_kernel_pids for it.
  - get_proc_pids() is temporarily replaced *inside this test process's
    imported module object* to omit the spawned PID. This does not hide
    the process from `ls /proc`, ps, htop, or any other process on the
    machine -- it only changes what this one test invocation of
    clc_daemon.get_proc_pids() returns, and only for the duration of the
    test. Once the test exits, clc_daemon.py behaves completely normally
    if imported/run elsewhere.

This must be run as root (same requirement as clc_daemon.py itself, since
fetch_ebpf_kernel_pids() shells out to `sudo bpftool map dump`).

Usage:
    sudo python3 test_clc_daemon.py --daemon-path /path/to/clc_daemon.py
"""
import argparse
import importlib.util
import os
import sys
import time
from unittest import mock


def load_daemon_module(path: str):
    spec = importlib.util.spec_from_file_location("clc_daemon_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def spawn_real_child(hold_seconds: float) -> int:
    """Real fork -> real sched_process_fork -> real active_kernel_pids entry."""
    pid = os.fork()
    if pid == 0:
        try:
            time.sleep(hold_seconds)
        finally:
            os._exit(0)
    return pid


def run_test(daemon, hold_seconds: float = 8.0):
    if os.getuid() != 0:
        print("This test needs root (same as clc_daemon.py itself, for bpftool).")
        sys.exit(1)

    print("[test] spawning real child process...")
    child_pid = spawn_real_child(hold_seconds)
    print(f"[test] child PID: {child_pid}")

    # Give sched_process_fork a moment to land in the eBPF map.
    time.sleep(0.75)

    kernel_pids_dict = daemon.fetch_ebpf_kernel_pids()
    if child_pid not in kernel_pids_dict:
        print("[test] FAIL: child PID never appeared in active_kernel_pids. "
              "Is the eBPF program actually loaded and attached?")
        os.kill(child_pid, 9)
        return False

    print(f"[test] confirmed: PID {child_pid} present in real active_kernel_pids map")

    real_get_proc_pids = daemon.get_proc_pids

    def patched_get_proc_pids():
        # Real scan, then remove exactly one PID -- only for this call,
        # only inside this test process.
        pids = real_get_proc_pids()
        pids.discard(child_pid)
        return pids

    with mock.patch.object(daemon, "get_proc_pids", side_effect=patched_get_proc_pids):
        print("[test] calling verify_hidden_pid() with real kernel state + "
              "one PID removed from this test's /proc view...")
        verdict = daemon.verify_hidden_pid(child_pid, kernel_pids_dict)

    print(f"[test] verdict: {verdict}")

    if verdict == "ROOTKIT":
        print("[test] PASS: CLC correctly flagged the mismatch.")
        result = True
    else:
        print(f"[test] FAIL: expected ROOTKIT, got {verdict}")
        result = False

    # Cleanup: let the real child finish naturally (it's not actually
    # hidden from the OS, so this is a normal wait).
    try:
        os.waitpid(child_pid, 0)
    except ChildProcessError:
        pass

    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--daemon-path", required=True,
                     help="path to clc_daemon.py to test")
    ap.add_argument("--hold", type=float, default=8.0,
                     help="seconds the test child stays alive")
    args = ap.parse_args()

    daemon = load_daemon_module(args.daemon_path)
    ok = run_test(daemon, hold_seconds=args.hold)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
