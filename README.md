# K-Guard Pipeline

An interactive kernel-space runtime monitoring and behavioral visualization pipeline driven by eBPF, `libbpf`, and NetworkX.

## Prerequisites

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev libelf-dev build-essential python3-pip
pip3 install -r requirements.txt
```

## Compilation
```make clean && make```

## Execution
```sudo ./monitor | python3 graphengine.py```

## Viewing the live Topology

The engine auto-saves updates to disk every 5seconds. Open the generated interactive
standalone webpage configuration directly inside browser.

On Linux: 
```xdg-open kguard_interactive_graph.html```
On macOS:
```open kguard_interactive_graph.html```
