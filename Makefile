CLANG = clang
GCC = gcc
CFLAGS = -g -O2 -D__TARGET_ARCH_x86 -target bpf -I/usr/include/x86_64-linux-gnu
LDFLAGS = -lbpf -lelf -lz

all: monitor

kguard.bpf.o: kguard.bpf.c
	$(CLANG) $(CFLAGS) -c kguard.bpf.c -o kguard.bpf.o

kguard.skel.h: kguard.bpf.o
	bpftool gen skeleton kguard.bpf.o > kguard.skel.h

monitor: kguard.skel.h monitor.c
	$(GCC) monitor.c -o monitor $(LDFLAGS)

clean:
	rm -f kguard.bpf.o kguard.skel.h monitor
