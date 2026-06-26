#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include "kguard.skel.h"

#define TYPE_EXEC         1
#define TYPE_FORK         2
#define TYPE_EXIT         3
#define TYPE_OPEN         4
#define TYPE_TCP_CONNECT  5

struct event_t {
    unsigned int pid;
    unsigned int ppid;
    unsigned int uid;
    unsigned int gid;
    unsigned long long timestamp_ns;
    unsigned long long start_time_ns;
    unsigned int event_type;
    long long retval;
    char comm[16];
    char filename[256];
    unsigned int dest_ip;
    unsigned short dest_port;
};

static int handle_event(void *ctx, void *data, size_t sz) {
    struct event_t *e = data;
    char ip_str[INET_ADDRSTRLEN] = "0.0.0.0";
    
    if (e->event_type == TYPE_TCP_CONNECT) {
        struct in_addr addr = { .s_addr = e->dest_ip };
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
    }

    printf("{\"timestamp_ns\": %llu, \"start_time_ns\": %llu, \"type_id\": %u, ", e->timestamp_ns, e->start_time_ns, e->event_type);
    
    switch (e->event_type) {
        case TYPE_EXEC:
            printf("\"event\": \"EXEC\", \"pid\": %u, \"ppid\": %u, \"uid\": %u, \"gid\": %u, \"comm\": \"%s\", \"target\": \"%s\"}\n", 
                   e->pid, e->ppid, e->uid, e->gid, e->comm, e->filename);
            break;
        case TYPE_OPEN:
            printf("\"event\": \"OPEN\", \"pid\": %u, \"ppid\": %u, \"uid\": %u, \"gid\": %u, \"comm\": \"%s\", \"target\": \"%s\", \"assigned_fd\": %lld}\n", 
                   e->pid, e->ppid, e->uid, e->gid, e->comm, e->filename, e->retval);
            break;
        case TYPE_FORK:
            printf("\"event\": \"FORK\", \"pid\": %u, \"ppid\": %u, \"comm\": \"%s\", \"child_pid\": %lld}\n", 
                   e->pid, e->ppid, e->comm, e->retval);
            break;
        case TYPE_EXIT:
            printf("\"event\": \"EXIT\", \"pid\": %u, \"comm\": \"%s\", \"exit_code\": %lld}\n", 
                   e->pid, e->comm, e->retval);
            break;
        case TYPE_TCP_CONNECT:
            printf("\"event\": \"NET_CONNECT\", \"pid\": %u, \"comm\": \"%s\", \"dest_ip\": \"%s\", \"dest_port\": %u}\n", 
                   e->pid, e->comm, ip_str, e->dest_port);
            break;
        default:
            printf("\"event\": \"UNKNOWN\"}\n");
            break;
    }
    
    fflush(stdout); 
    return 0;
}

int main(void) {
    struct kguard_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    struct rlimit rlim = { .rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    skel = kguard_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load K-Guard kernel skeleton\n");
        return 1;
    }

    err = kguard_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to mount tracepoints\n");
        kguard_bpf__destroy(skel);
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to open shared ring buffer\n");
        kguard_bpf__destroy(skel);
        return 1;
    }

    while (1) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            break;
        }
    }

    ring_buffer__free(rb);
    kguard_bpf__destroy(skel);
    return 0;
}