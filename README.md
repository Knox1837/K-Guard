# K-Guard Pipeline

An interactive kernel-space runtime monitoring and behavioral visualization pipeline driven by eBPF, `libbpf`, and NetworkX.

## Prerequisites

Install the required system build dependencies and generate the `vmlinux.h` header file from your running kernel:

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev libelf-dev build-essential bpftool python3-pip
pip3 install -r requirements.txt

# Generate the kernel definition header
bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
```

## Compilation
```
make clean && make
```

## Execution
```
sudo ./monitor | python3 src/user/graphengine.py
```
or
```
sudo bash -c './monitor | python3 src/user/graphengine.py'
```

## Viewing the live Topology

The engine auto-saves updates to disk every 5seconds. Open the generated interactive
standalone webpage configuration directly inside browser.

On Linux: 
```
xdg-open kguard_interactive_graph.html
```
On macOS:
```
open kguard_interactive_graph.html
```
