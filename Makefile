CLANG = clang
GCC = gcc

# Added -I. so files inside sub-directories like src/kernel/kguard.bpf.c can find vmlinux.h wherever it is generated
CFLAGS = -g -O2 -D__TARGET_ARCH_x86 -target bpf -I./include -I. -I/usr/include/x86_64-linux-gnu
LDFLAGS = -lbpf -lelf -lz

all: monitor

# 1. Compile the eBPF kernel code from src/kernel/
src/kernel/kguard.bpf.o: src/kernel/kguard.bpf.c
	$(CLANG) $(CFLAGS) -c src/kernel/kguard.bpf.c -o src/kernel/kguard.bpf.o

# 2. Generate the skeleton header file
src/user/kguard.skel.h: src/kernel/kguard.bpf.o
	bpftool gen skeleton src/kernel/kguard.bpf.o > src/user/kguard.skel.h

# 3. Compile the user-space monitor binary using the skeleton
monitor: src/user/kguard.skel.h src/user/monitor.c
	$(GCC) src/user/monitor.c -o monitor $(LDFLAGS)

# 4. Clean up all generated artifacts
clean:
	rm -f src/kernel/kguard.bpf.o src/user/kguard.skel.h monitor
