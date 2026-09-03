#!/usr/bin/env python3
"""
intent_shim.py: Section 3.6.2: IntentShim.

A lightweight subprocess wrapper for AI agent frameworks. Before each fork/exec,
IntentShim writes the agent's task description into the kernel's intent_map BPF
hash, keyed by the child PID, so monitor.c can attach that declared intent to
FILE_OPEN events from that process.

Ordering guarantee
-------------------
Section 3.6.2 requires the map write to happen in user space before the child
begins execution. A plain fork/exec has no guaranteed ordering, so the child
could open files before the parent finishes bpftool map update. IntentShim
avoids this race with a pipe rendezvous around raw os.fork() and os.execvp():

1. Create a pipe and fork.
2. The child blocks on a read before exec.
3. The parent writes the intent_map entry with bpftool and then writes a byte
   to the pipe.
4. The child unblocks and continues directly into exec.

This ensures the intent write completes before the child starts running.

Why not subprocess.Popen
------------------------
An earlier version used subprocess.Popen with preexec_fn and SIGSTOP/SIGCONT.
That approach is still racy and, more importantly, Popen blocks waiting for its
internal O_CLOEXEC pipe to close. If the child stops before exec, that pipe
never closes and the parent hangs. Raw os.fork()/os.execvp() avoids that
failure mode entirely.

Caveats
-------
- monitor must already be running so the map is loaded.
- intent_map is resolved by name via bpftool, using the same pattern as
  clc_daemon.py.
- bpftool must be installed and invoked with sudo.
"""
from __future__ import annotations

import os
import shlex
import subprocess
import sys
from typing import Optional, Sequence, Union

MAP_NAME = "intent_map"
TASK_MAX_BYTES = 127  # + 1 NUL byte = 128, matches struct intent_val_t in kguard.bpf.c


def _pid_key_bytes(pid: int) -> str:
    """4-byte little-endian PID key, formatted for `bpftool map update ... key`."""
    raw = pid.to_bytes(4, byteorder="little")
    return " ".join(f"0x{b:02x}" for b in raw)


def _task_value_bytes(task_description: str) -> str:
    """NUL-padded 128-byte value, formatted for `bpftool map update ... value`."""
    truncated = task_description.encode("utf-8", errors="replace")[:TASK_MAX_BYTES]
    padded = truncated + b"\x00" * (128 - len(truncated))
    return " ".join(f"0x{b:02x}" for b in padded)


class IntentShimError(RuntimeError):
    """Raised internally when the intent_map write itself fails (bpftool error, map missing, etc)."""


_BPFTOOL_TIMEOUT_SEC = 5  # a healthy `bpftool` call is near-instant; never block the caller

# `-n`: never prompt for a password. If passwordless sudo isn't configured
# for bpftool, the call fails fast (returncode != 0) instead of hanging
# the whole pipeline waiting on a TTY that doesn't exist in an agent's
# subprocess context.
_SUDO_NON_INTERACTIVE = "sudo -n"


def _run_bpftool(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=_BPFTOOL_TIMEOUT_SEC,
    )


def _write_intent(pid: int, task_description: str) -> None:
    key = _pid_key_bytes(pid)
    value = _task_value_bytes(task_description)
    cmd = f"{_SUDO_NON_INTERACTIVE} bpftool map update name {MAP_NAME} key {key} value {value}"
    try:
        result = _run_bpftool(cmd)
    except (subprocess.TimeoutExpired, OSError) as e:
        raise IntentShimError(f"Failed to write intent for PID {pid} into {MAP_NAME}: {e}") from e
    if result.returncode != 0:
        raise IntentShimError(
            f"Failed to write intent for PID {pid} into {MAP_NAME}: "
            f"{(result.stderr or result.stdout).strip()}. "
            f"Is `monitor` running with the intent_map map loaded, and is "
            f"passwordless sudo configured for bpftool?"
        )


def _clear_intent(pid: int) -> None:
    """
    Best-effort cleanup of a still-pending intent entry (e.g. if the shim
    itself is interrupted). Not required for correctness: the kernel also
    clears intent_map on process exit (see handle_exit in kguard.bpf.c),
    so a failure here is silently non-fatal.
    """
    key = _pid_key_bytes(pid)
    try:
        _run_bpftool(f"{_SUDO_NON_INTERACTIVE} bpftool map delete name {MAP_NAME} key {key}")
    except (subprocess.TimeoutExpired, OSError):
        pass


def _exit_code_from_status(status: int) -> int:
    """Mirror subprocess.Popen.returncode's convention: negative signal
    number if killed by a signal, else the plain exit status."""
    if os.WIFSIGNALED(status):
        return -os.WTERMSIG(status)
    return os.WEXITSTATUS(status)


class _ShimProcess:
    """
    Minimal, stdlib-only process handle for a child launched by
    IntentShim.run(). Deliberately NOT a subprocess.Popen (see the module
    docstring's "Why not subprocess.Popen" section) — this only exposes
    the small subset of Popen's API (`pid`, `wait()`, `poll()`,
    `returncode`) that callers actually need.
    """

    def __init__(self, pid: int):
        self.pid = pid
        self.returncode: Optional[int] = None

    def wait(self) -> int:
        if self.returncode is None:
            _, status = os.waitpid(self.pid, 0)
            self.returncode = _exit_code_from_status(status)
        return self.returncode

    def poll(self) -> Optional[int]:
        if self.returncode is None:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid != 0:
                self.returncode = _exit_code_from_status(status)
        return self.returncode


class IntentShim:
    """
    Wraps subprocess creation for an AI agent framework, registering each
    child's declared task description in K-Guard's intent_map before it
    starts running.

    Usage:
        shim = IntentShim()
        proc = shim.run(
            ["python3", "backup_script.py"],
            task_description="Back up project config files to S3",
        )
        proc.wait()
    """

    def __init__(self, enabled: bool = True):
        # `enabled=False` lets an agent framework no-op this shim in
        # environments without K-Guard/bpftool (e.g. plain local dev),
        # rather than forcing every call site to branch on availability.
        self.enabled = enabled

    def run(
        self,
        cmd: Union[str, Sequence[str]],
        task_description: str,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
    ) -> Union[subprocess.Popen, "_ShimProcess"]:
        """
        Launches `cmd`, registering `task_description` against the
        child's PID in intent_map before it begins executing (see the
        module docstring's pipe-rendezvous protocol).

        A failed intent_map write is logged as a warning but never blocks
        or kills the child — per Section 3.6.3 step 1, a PID with no
        intent entry simply falls back to the standard anomaly pipeline,
        which is a safe (if less informative) degradation, not an error
        condition worth failing the agent's actual task over.
        """
        argv = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)

        if not self.enabled:
            return subprocess.Popen(argv, cwd=cwd, env=env)

        read_fd, write_fd = os.pipe()
        pid = os.fork()

        if pid == 0:
            # --- Child ---
            try:
                os.close(write_fd)
                os.read(read_fd, 1)  # blocks until the parent has written our intent
                os.close(read_fd)
                if cwd is not None:
                    os.chdir(cwd)
                if env is not None:
                    os.execvpe(argv[0], argv, env)
                else:
                    os.execvp(argv[0], argv)
            except Exception:
                pass  # can't safely log/raise post-fork; just fall through to _exit
            os._exit(127)  # only reached if exec() itself failed

        # --- Parent ---
        os.close(read_fd)
        proc = _ShimProcess(pid)
        try:
            _write_intent(pid, task_description)
        except IntentShimError as e:
            print(f"[IntentShim] WARNING: {e}", file=sys.stderr)
        finally:
            os.write(write_fd, b"\x00")
            os.close(write_fd)

        return proc


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Run a command under K-Guard's Intent-Aware IntentShim (Section 3.6.2)."
    )
    parser.add_argument("--task", required=True, help="Natural-language task description")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to run, e.g. -- python3 script.py")
    args = parser.parse_args()

    if not args.command:
        parser.error("no command given")

    shim = IntentShim()
    process = shim.run(args.command, task_description=args.task)
    process.wait()
    raise SystemExit(process.returncode)
