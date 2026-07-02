#define _POSIX_C_SOURCE 199309L
#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdlib.h>
#include "kguard.skel.h"

#define TYPE_EXEC         1
#define TYPE_FORK         2
#define TYPE_EXIT         3
#define TYPE_OPEN         4
#define TYPE_TCP_CONNECT  5
#define PID_HASH_SIZE 1024

struct pid_degree_t {
    unsigned int pid;
    int in_degree;
    int out_degree;
    struct pid_degree_t *next;
};

static struct pid_degree_t *pid_table[PID_HASH_SIZE] = {NULL};

static struct pid_degree_t* get_or_create_pid_entry(unsigned int pid) { // Helper function to find or create a tracking entry for a PID
    unsigned int slot = pid % PID_HASH_SIZE;
    struct pid_degree_t *curr = pid_table[slot];
    
    while (curr) {
        if (curr->pid == pid) return curr;
        curr = curr->next;
    }
    
    // Allocate new entry if it doesn't exist
    struct pid_degree_t *new_entry = calloc(1, sizeof(struct pid_degree_t));
    if (!new_entry) return NULL;
    
    new_entry->pid = pid;
    new_entry->next = pid_table[slot];
    pid_table[slot] = new_entry;
    return new_entry;
}

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

FILE *jsonl_file = NULL;

void generate_session_id(char *buf) {
    srand(time(NULL));
    sprintf(buf, "%04x%04x-%04x-%04x-%04x-%04x%04x%04x",
            rand() % 0xffff, rand() % 0xffff, rand() % 0xffff,
            (rand() % 0x0fff) | 0x4000, (rand() % 0x3fff) | 0x8000,
            rand() % 0xffff, rand() % 0xffff, rand() % 0xffff);
}

static int handle_event(void *ctx, void *data, size_t sz) {
    struct event_t *e = data;
    char ip_str[INET_ADDRSTRLEN] = "0.0.0.0";

    if (e->event_type == TYPE_TCP_CONNECT) {
        struct in_addr addr = { .s_addr = e->dest_ip };
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
    }

    struct pid_degree_t *proc_stats = get_or_create_pid_entry(e->pid);

    switch (e->event_type) {
        case TYPE_EXEC:
            if (proc_stats) proc_stats->out_degree++;
            break;
        case TYPE_OPEN:
            if (proc_stats) proc_stats->out_degree++;
            break;
        case TYPE_FORK:
            if (proc_stats) proc_stats->out_degree++; //parent gets an outgoing edge to the child
            struct pid_degree_t *child_stats = get_or_create_pid_entry((unsigned int)e->retval);//child gets a incoming edge from the parent
            if (child_stats) child_stats->in_degree++;
            break;
        case TYPE_EXIT:
            break;
        case TYPE_TCP_CONNECT:
            if (proc_stats) proc_stats->out_degree++;
            break;
        default:
            break;
    }
    int out_degree = proc_stats ? proc_stats->out_degree : 0;
    int in_degree = proc_stats ? proc_stats->in_degree : 0;
    int connections = out_degree + in_degree;

    printf("{\"timestamp_ns\": %llu, \"start_time_ns\": %llu, \"type_id\": %u, \"out_degree\": %d, \"in_degree\": %d, ", 
           e->timestamp_ns, e->start_time_ns, e->event_type, out_degree, in_degree);
    

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

    // Get wall time as a float (seconds since epoch)
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    double wall_time = ts.tv_sec + (ts.tv_nsec / 1e9);

    const char *event_str = "UNKNOWN";
    switch (e->event_type) {
        case TYPE_EXEC:        event_str = "EXEC";        break;
        case TYPE_FORK:        event_str = "FORK";        break;
        case TYPE_EXIT:        event_str = "EXIT";        break;
        case TYPE_OPEN:        event_str = "OPEN";        break;
        case TYPE_TCP_CONNECT: event_str = "NET_CONNECT"; break;
    }

    // Baseline placeholders for graph engine features
    float max_len = 0.0f;
    float max_entropy = 0.0f;
    int contains_sensitive = 0;
    const char *status = "";
    const char *label = "";

    // print in the CSV structure
    // session_id, ts_ns, wall_time, node_id, pid, uid, gid, comm, event, out_degree, in_degree, connections, max_len, max_entropy, contains_sensitive, status, label
    // printf("%s,%llu,%.6f,proc_%u_%llu,%u,%u,%u,\"%s\",\"%s\",%d,%d,%d,%.2f,%.2f,%d,\"%s\",\"%s\"\n",
    //        session_id,
    //        e->timestamp_ns,
    //        wall_time,
    //        e->pid, e->start_time_ns,
    //        e->pid, e->uid, e->gid,
    //        e->comm,
    //        event_str,
    //        out_degree,
    //        in_degree,
    //        connections,
    //        max_len,
    //        max_entropy,
    //        contains_sensitive,
    //        status,
    //        label);
    
    if (jsonl_file) {
         fprintf(jsonl_file, "{\"timestamp_ns\": %llu, \"wall_time\": %.6f, \"node_id\": \"proc_%u_%llu\", \"pid\": %u, \"uid\": %u, \"gid\": %u, \"comm\": \"%s\", \"event\": \"%s\", \"out_degree\": %d, \"in_degree\": %d, \"connections\": %d, \"max_len\": %.2f, \"max_entropy\": %.2f, \"contains_sensitive\": %d, \"status\": \"%s\", \"label\": \"%s\"}\n", //this is a jsonl format where each row is a valid json object
            e->timestamp_ns, //exact time event was captured in nanoseconds(since system was booted up)
            wall_time, //Unix timestamp (seconds since 1970) when the log entry was recorded
            e->pid, //Maps to first node_id: process identifier for building graph node uniqueness
            e->start_time_ns, //proc launch time in nanoseconds
            e->pid, // maps to next node_id: the literal, raw system Process ID of the application
            e->uid, //user running the program 0 for root, 1000 for first user, etc
            e->gid, //group ID of the user running the program
            e->comm,//short executable name of the process like python
            event_str,//text label of action like EXEC, FORK 
            out_degree,
            in_degree,
            connections,//in_degree + out_degree
            max_len, //longest path or command argument length
            max_entropy, //information randomness score used to identify packed or encrypted malware
            contains_sensitive, //binary to show if the process has sensitive data
            status, //placeholder tracking pipeline flags or runtime states
            label   //target data category or classification label for the process
        );

        /*fprintf(jsonl_file,  "%llu,%.6f,\"proc_%u_%llu\",%u,%u,%u,\"%s\",\"%s\",%d,%d,%d,%.2f,%.2f,%d,\"%s\",\"%s\"\n", //This is equivalent to a csv format but in jsonl format
            e->timestamp_ns,
            wall_time,
            e->pid, e->start_time_ns,
            e->pid, e->uid, e->gid,
            e->comm,
            event_str,
            out_degree,
            in_degree,
            connections,
            max_len,
            max_entropy,
            contains_sensitive,
            status,
            label);*/
        fflush(jsonl_file);
    }
    return 0;
}

int main(void) {
    struct kguard_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    time_t raw_time = time(NULL);
    struct tm *time_info = localtime(&raw_time);

    char filepath[256];
    snprintf(filepath, sizeof(filepath), "./logs/session_%04d_%02d_%02d_%02d_%02d_%02d.jsonl", //./logs/session_YYYY_MM_DD_HH_MM_SS.jsonl
             time_info->tm_year + 1900, // tm_year is years since 1900
             time_info->tm_mon + 1,     // tm_mon is 0-11
             time_info->tm_mday,
             time_info->tm_hour,
             time_info->tm_min,
             time_info->tm_sec);

    jsonl_file = fopen(filepath, "w");
    if (!jsonl_file) {
        fprintf(stderr, "Failed to create ML log file: %s\n", filepath);
        return 1;
    }

    struct rlimit rlim = { .rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    skel = kguard_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load K-Guard kernel skeleton\n");
        fclose(jsonl_file);
        return 1;
    }

    err = kguard_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to mount tracepoints\n");
        kguard_bpf__destroy(skel);
        fclose(jsonl_file);
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to open shared ring buffer\n");
        kguard_bpf__destroy(skel);
        fclose(jsonl_file);
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
    fclose(jsonl_file);
    return 0;
}