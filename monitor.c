#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>
#include "kguard.skel.h"

#define TYPE_EXEC 1
#define TYPE_OPEN 2

struct event_t {
    unsigned int pid;
    unsigned int event_type;
    char comm[16];
    char filename[64];
};

// ONLY ONE instance of handle_event allowed here
static int handle_event(void *ctx, void *data, size_t sz) {
    struct event_t *e = data;
    
    // Output clean JSON lines to stdout
    if (e->event_type == TYPE_EXEC) {
        printf("{\"type\": \"EXEC\", \"pid\": %u, \"comm\": \"%s\", \"target\": \"%s\"}\n", 
               e->pid, e->comm, e->filename);
    } else if (e->event_type == TYPE_OPEN) {
        printf("{\"type\": \"OPEN\", \"pid\": %u, \"comm\": \"%s\", \"target\": \"%s\"}\n", 
               e->pid, e->comm, e->filename);
    }
    fflush(stdout); // Instantly streams data down the pipe without delay
    return 0;
}

int main(void) {
    struct kguard_bpf *skel = kguard_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load skeleton\n");
        return 1;
    }

    kguard_bpf__attach(skel);

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to initialize ring buffer\n");
        return 1;
    }

    // Keep loop active
    while (ring_buffer__poll(rb, 100) >= 0) {}

    return 0;
}
