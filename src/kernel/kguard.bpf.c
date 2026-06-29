#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

// Section 3.2 Event Categories
#define TYPE_EXEC         1
#define TYPE_FORK         2
#define TYPE_EXIT         3
#define TYPE_OPEN         4
#define TYPE_TCP_CONNECT  5

// Section 3.3 Struct: Composite key mapping to unique mounted filesystem lifetime
struct dedup_key_t {
    unsigned int pid;
    unsigned long inode;
    unsigned int dev;
};

// FIX: wrapper struct so the BPF map value type macro has a clean named type
// to hold the filename string stashed between sys_enter_openat and sys_exit_openat.
struct fname_buf_t {
    char name[256];
};

// Comprehensive event footprint data structure matching Section 3.2 and 3.3
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

// 8 MB Shared Ring Buffer allocation specified by Section 3.2
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024); 
} rb SEC(".maps");

// SECTION 3.3 MAP: Kernel-Level Edge Deduplication Hash Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct dedup_key_t);
    __type(value, unsigned long long); 
} edge_dedup_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, unsigned long long);     // pid_tgid
    __type(value, struct fname_buf_t);
} open_filename_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct fname_buf_t);
} fname_scratch SEC(".maps");

// Immutable Kernel Tracking Map for CLC
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, unsigned int);         // Key: PID
    __type(value, unsigned long long); // Value: Timestamp
} active_kernel_pids SEC(".maps");

// Inline helper to gather the base-level container and security context metrics
static __always_inline void fill_common_context(struct event_t *e, unsigned int type) {
    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    unsigned long long uid_gid  = bpf_get_current_uid_gid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    e->pid = pid_tgid >> 32;
    e->uid = uid_gid;
    e->gid = uid_gid >> 32;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type = type;
    e->retval = 0;
    e->dest_ip = 0;
    e->dest_port = 0;

    struct task_struct *real_parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(real_parent, tgid);
    e->start_time_ns = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// 1. PROCESS EXECUTION
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common_context(e, TYPE_EXEC);
    
    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 2a. FIX: CAPTURE FILENAME AT ENTRY — the user-space pathname pointer
// (ctx->args[1] for openat(int dfd, const char *filename, int flags, mode_t mode))
// is only safely readable at syscall entry. We stash it keyed by pid_tgid
// so the exit hook can attach the real path to the emitted event.
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx) {
    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    const char *filename_ptr = (const char *)ctx->args[1];

    // FIX: use the per-CPU scratch slot instead of a 256-byte stack local —
    // see the fname_scratch map definition above for why.
    unsigned int zero = 0;
    struct fname_buf_t *buf = bpf_map_lookup_elem(&fname_scratch, &zero);
    if (!buf) return 0;  // verifier requires this check; for a 1-entry array map it never actually fails

    __builtin_memset(buf, 0, sizeof(*buf));
    bpf_probe_read_user_str(&buf->name, sizeof(buf->name), filename_ptr);

    bpf_map_update_elem(&open_filename_map, &pid_tgid, buf, BPF_ANY);
    return 0;
}

// 2b. FILE OPENING OPERATIONS WITH SECTION 3.3 DEDUPLICATION (Hooked at Exit)
SEC("tracepoint/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx) {
    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    long fd = ctx->ret;

    unsigned int zero = 0;
    struct fname_buf_t *fname_local = bpf_map_lookup_elem(&fname_scratch, &zero);
    if (!fname_local) return 0;  // verifier requires this check; never actually fails for a 1-entry array map
    __builtin_memset(fname_local, 0, sizeof(*fname_local));

    struct fname_buf_t *stashed = bpf_map_lookup_elem(&open_filename_map, &pid_tgid);
    if (stashed) {
        __builtin_memcpy(fname_local, stashed, sizeof(*fname_local));
    }
    bpf_map_delete_elem(&open_filename_map, &pid_tgid);

    if (fd < 0) return 0; // Skip if open failed

    unsigned int pid = pid_tgid >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // Verifier Fix: Explicit step-by-step kernel space pointer walks to avoid scalar errors
    struct files_struct *files = NULL;
    bpf_probe_read_kernel(&files, sizeof(files), &task->files);

    if (files) {
        struct fdtable *fdt = NULL;
        bpf_probe_read_kernel(&fdt, sizeof(fdt), &files->fdt);

        if (fdt) {
            struct file **fd_array = NULL;
            unsigned int max_fds = 0;

            bpf_probe_read_kernel(&fd_array, sizeof(fd_array), &fdt->fd);
            bpf_probe_read_kernel(&max_fds, sizeof(max_fds), &fdt->max_fds);

            // Bounds check the fd array safely for the verifier
            if (fd_array && fd < max_fds) {
                struct file *f = NULL;
                bpf_probe_read_kernel(&f, sizeof(f), &fd_array[fd]);

                if (f) {
                    struct inode *file_inode = BPF_CORE_READ(f, f_inode);
                    if (file_inode) {
                        struct dedup_key_t key = {};
                        key.pid = pid;
                        key.inode = BPF_CORE_READ(file_inode, i_ino);
                        key.dev = BPF_CORE_READ(file_inode, i_sb, s_dev);

                        unsigned long long *last_seen = bpf_map_lookup_elem(&edge_dedup_map, &key);
                        unsigned long long current_time = bpf_ktime_get_ns();

                        // SECTION 3.3 FILTER: Short-circuit duplicate events (5-second TTL)
                        if (last_seen && (current_time - *last_seen < 5000000000ULL)) {
                            return 0; 
                        }
                        bpf_map_update_elem(&edge_dedup_map, &key, &current_time, BPF_ANY);
                    }
                }
            }
        }
    }

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common_context(e, TYPE_OPEN);
    e->retval = fd;

    __builtin_memcpy(e->filename, fname_local->name, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 3. PROCESS FORK/CLONE
SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx) {
    unsigned int child_pid = ctx->child_pid;
    unsigned long long ts = bpf_ktime_get_ns();

    // Insert the newly created child PID into out CLC validation map
    bpf_map_update_elem(&active_kernel_pids, &child_pid, &ts, BPF_ANY);
    
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common_context(e, TYPE_FORK);
    
    e->retval = ctx->child_pid; 
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 4. PROCESS TERMINATION
SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx) {
    unsigned int pid = bpf_get_current_pid_tgid() >> 32;

    // Delete the exiting PID from the CLC validation map
    bpf_map_delete_elem(&active_kernel_pids, &pid);

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common_context(e, TYPE_EXIT);
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->retval = BPF_CORE_READ(task, exit_code);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 5. NETWORK CONNECTION ESTABLISHMENT
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(handle_tcp_v4_connect, struct sock *sk) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common_context(e, TYPE_TCP_CONNECT);

    e->dest_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    unsigned short dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    e->dest_port = __builtin_bswap16(dport); 

    bpf_snprintf(e->filename, sizeof(e->filename), "Network TCP Outbound Connection", NULL, 0);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
