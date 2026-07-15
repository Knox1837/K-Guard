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
#define TYPE_TCP_CLOSE    6  

// Expanded attack-surface coverage event types (Section 4)
#define TYPE_TCP_ACCEPT    7   // inbound connection accepted (kretprobe/inet_csk_accept)
#define TYPE_DUP_REDIRECT  8   // dup2/dup3'd a socket onto stdin/stdout/stderr — THE reverse-shell signature
#define TYPE_CREDS_CHANGE  9   // commit_creds() — uid/gid actually changed (privilege escalation choke point)
#define TYPE_PTRACE        10  // ptrace() syscall — process injection / credential dumping primitive
#define TYPE_MPROTECT_RWX  11  // mprotect() requesting WRITE+EXEC together — classic shellcode pattern
#define TYPE_MEMFD_CREATE  12  // memfd_create() — fileless execution primitive
#define TYPE_UNLINK        13  // unlinkat() — file deletion (self-cleanup / anti-forensics)
#define TYPE_RENAME        14  // renameat2() — masquerading
#define TYPE_CHMOD         15  // fchmodat() — permission changes (setuid backdoors)
#define TYPE_MODULE_LOAD   16  // init_module()/finit_module() — kernel module load (rootkit territory)
#define TYPE_MODULE_UNLOAD 17  // delete_module()
#define TYPE_RAW_SOCKET    18  // socket(..., SOCK_RAW, ...) — packet crafting/sniffing

// Since tcp_close() is only ever called for TCP sockets, we can hardcode the protocol number which is 6 for TCP.
#define IPPROTO_TCP_VAL   6

// Protection flags for mprotect() and mmap()
#define PROT_WRITE_VAL     0x2
#define PROT_EXEC_VAL      0x4
#define SOCK_RAW_VAL       3
#define SOCK_TYPE_MASK_VAL 0xFF
#define S_IFMT_VAL         0170000
#define S_IFSOCK_VAL       0140000

// To holde socket data
struct socket_stats {
	u64 bytes_sent;
	u64 bytes_recv;
	u64 start_ts;
	u32 parent_pid;
	char parent_comm[16];
};

// Map to track active socket telementry
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32); // PID as key
	__type(value, struct socket_stats);
} socket_metrics SEC(".maps");

// Update counters on every send/receive for TCP and UDP sockets. 
// This is done in the kprobes for tcp_sendmsg, tcp_recvmsg, udp_sendmsg, and udp_recvmsg. 
// The counters are stored in the socket_metrics map, keyed by PID.
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct socket_stats *stats = bpf_map_lookup_elem(&socket_metrics, &pid);
	if (stats) {
		stats->bytes_sent += size;
	}
	return 0;
}
SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(handle_tcp_recvmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct socket_stats *stats = bpf_map_lookup_elem(&socket_metrics, &pid);
    if (stats && len > 0 && len < 65535) {
        stats->bytes_recv += len; 
    }
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(handle_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct socket_stats *stats = bpf_map_lookup_elem(&socket_metrics, &pid);
	if (stats) {
		stats->bytes_sent += size;
	}
	return 0;
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(handle_udp_recvmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct socket_stats *stats = bpf_map_lookup_elem(&socket_metrics, &pid);
    if (stats && len > 0 && len < 65535) {
        stats->bytes_recv += len; 
    }
    return 0;
}

// Section 3.3 Struct: Composite key mapping to unique mounted filesystem lifetime
struct dedup_key_t {
    unsigned int pid;
    unsigned long inode;
    unsigned int dev;
};

// to hold the filename string stashed between sys_enter_openat and sys_exit_openat.
struct fname_buf_t {
    char name[256];
    
    // This holds the open flags (O_WRONLY, O_APPEND, O_CREAT, etc.) from sys_enter_openat so we can emit them in the TYPE_OPEN event at exit.
    int flags;
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
    unsigned int dest_ip; // Big-endian network byte order for TCP/UDP connections so use __builtin_bswap16() when reading from the kernel struct sock.
    unsigned short dest_port; // Big-endian network byte order for TCP/UDP connections so use __builtin_bswap16() when reading from the kernel struct sock.

    // These fields are only populated for TYPE_TCP_CLOSE events, and are used to capture the full lifetime summary of a TCP connection.
    unsigned int src_ip;          // source IP, host byte order
    unsigned short src_port;      // source port, host byte order
    unsigned char protocol;       // IPPROTO_TCP_VAL for now; room to add UDP later
    unsigned long long bytes_sent;   // total bytes sent over the socket's lifetime
    unsigned long long bytes_recv;   // total bytes received over the socket's lifetime
    unsigned long long duration_ns;  // total duration of the connection in nanoseconds

    // Generic argument fields for syscall-specific data (e.g., open flags, dup2 oldfd, etc.)
    unsigned long long arg1;
    unsigned long long arg2;
    char extra_str[128];
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

    // Zero out the TCP lifetime summary fields as bpf_ringbuf_reserve() does not zero the memory for us.
    // These fields are only populated for TYPE_TCP_CLOSE events.
    e->src_ip = 0;
    e->src_port = 0;
    e->protocol = 0;
    e->bytes_sent = 0;
    e->bytes_recv = 0;
    e->duration_ns = 0;
    e->arg1 = 0;
    e->arg2 = 0;
    e->extra_str[0] = '\0';

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

    // Capture the first three command-line arguments (argv[1], argv[2], argv[3]) into extra_str for context.
    // this does not capture all arguments, below code needs to be updated to capture all arguments if needed. VERY VERY IMPORTANT 
    const char **argv = (const char **)ctx->args[1];
    const char *arg1p = NULL;
    const char *arg2p = NULL;
    bpf_probe_read_user(&arg1p, sizeof(arg1p), &argv[1]);
    bpf_probe_read_user(&arg2p, sizeof(arg2p), &argv[2]);
    if (arg1p) bpf_probe_read_user_str(&e->extra_str[0],  64, arg1p);
    if (arg2p) bpf_probe_read_user_str(&e->extra_str[64], 64, arg2p);
    
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
    buf->flags = (int)ctx->args[2]; //stash open flags (O_WRONLY, O_APPEND, O_CREAT, ...) too

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
    e->arg1 = (unsigned long long)(unsigned int)fname_local->flags; // O_WRONLY/O_APPEND/O_CREAT/... — read vs write intent

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
SEC("kprobe/tcp_connect")
int BPF_KPROBE(handle_tcp_connect, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct socket_stats stats = {};
    stats.start_ts = bpf_ktime_get_ns();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    stats.parent_pid = BPF_CORE_READ(task, real_parent, tgid); // Parent PID
    bpf_probe_read_kernel_str(&stats.parent_comm, sizeof(stats.parent_comm), BPF_CORE_READ(task, real_parent, comm));
    bpf_map_update_elem(&socket_metrics, &pid, &stats, BPF_ANY);
	
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

// 6. NETWORK CONNECTION ACCEPTED (INBOUND)
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(handle_tcp_accept, struct sock *newsk) {
    if (!newsk) return 0; // accept() call didn't actually hand back a connection

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common_context(e, TYPE_TCP_ACCEPT);

    // NOTE role reversal vs TYPE_TCP_CONNECT: there, dest_ip/dest_port is who
    // WE called out to. Here, dest_ip/dest_port is the remote peer that just
    // connected IN to us; src_ip/src_port is our own listening-side address.
    e->dest_ip   = BPF_CORE_READ(newsk, __sk_common.skc_daddr);
    e->dest_port = __builtin_bswap16(BPF_CORE_READ(newsk, __sk_common.skc_dport));
    e->src_ip    = BPF_CORE_READ(newsk, __sk_common.skc_rcv_saddr);
    e->src_port  = BPF_CORE_READ(newsk, __sk_common.skc_num);

    bpf_snprintf(e->filename, sizeof(e->filename), "Network TCP Inbound Accept", NULL, 0);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// end

// Hook for TCP socket closure.
SEC("kprobe/tcp_close")
int BPF_KPROBE(handle_tcp_close, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // We can extend this to handle inbound connections too
    struct socket_stats *stats = bpf_map_lookup_elem(&socket_metrics, &pid);
    if (!stats) {
        return 0;
    }
    // copy the entire map value to a local variable to avoid potential issues with concurrent updates while we are reading the data for the event.
    struct socket_stats local_stats = *stats;

    u64 end_ts = bpf_ktime_get_ns();

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        // Even if we can't emit the event, we still want to clean up the socket_metrics map to avoid memory leaks.
        bpf_map_delete_elem(&socket_metrics, &pid);
        return 0;
    }

    fill_common_context(e, TYPE_TCP_CLOSE);

    e->dest_ip   = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->dest_port = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
    e->src_ip    = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->src_port  = BPF_CORE_READ(sk, __sk_common.skc_num); // already host byte order, no bswap needed

    e->protocol   = IPPROTO_TCP_VAL;
    e->bytes_sent = local_stats.bytes_sent;
    e->bytes_recv = local_stats.bytes_recv;
    e->duration_ns = end_ts - local_stats.start_ts;

    bpf_snprintf(e->filename, sizeof(e->filename), "Network TCP Connection Closed", NULL, 0);

    bpf_ringbuf_submit(e, 0);

    bpf_map_delete_elem(&socket_metrics, &pid);
    return 0;
}

// SECTION 4: EXPANDED ATTACK-SURFACE COVERAGE

// Shared Helpers 
// Resolve fd -> struct file* for the CURRENT task. 
static __always_inline struct file *lookup_fd_file(struct task_struct *task, unsigned int fd) {
    struct files_struct *files = NULL;
    bpf_probe_read_kernel(&files, sizeof(files), &task->files);
    if (!files) return NULL;

    struct fdtable *fdt = NULL;
    bpf_probe_read_kernel(&fdt, sizeof(fdt), &files->fdt);
    if (!fdt) return NULL;

    struct file **fd_array = NULL;
    unsigned int max_fds = 0;
    bpf_probe_read_kernel(&fd_array, sizeof(fd_array), &fdt->fd);
    bpf_probe_read_kernel(&max_fds, sizeof(max_fds), &fdt->max_fds);
    if (!fd_array || fd >= max_fds) return NULL;

    struct file *f = NULL;
    bpf_probe_read_kernel(&f, sizeof(f), &fd_array[fd]);
    return f;
}

// Is this struct file* actually a socket? 
static __always_inline int file_is_socket(struct file *f) {
    if (!f) return 0;
    struct inode *inode = BPF_CORE_READ(f, f_inode);
    if (!inode) return 0;
    unsigned short mode = BPF_CORE_READ(inode, i_mode);
    return (mode & S_IFMT_VAL) == S_IFSOCK_VAL;
}

// For a socket fd, file->private_data is a struct socket*, and struct
// socket->sk is the underlying struct sock 
static __always_inline struct sock *sock_from_file(struct file *f) {
    struct socket *sock = BPF_CORE_READ(f, private_data);
    if (!sock) return NULL;
    return BPF_CORE_READ(sock, sk);
}

// 7. FD REDIRECT (the reverse-shell signature) 
static __always_inline int handle_dup_redirect(int oldfd, int newfd) {
    if (newfd < 0 || newfd > 2) return 0; // only stdin/stdout/stderr are interesting here

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct file *f = lookup_fd_file(task, (unsigned int)oldfd);
    if (!file_is_socket(f)) return 0;

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common_context(e, TYPE_DUP_REDIRECT);
    e->retval = newfd;               // which stdio fd (0/1/2) got overwritten
    e->arg1 = (unsigned long long)oldfd; // which fd held the socket

    struct sock *sk = sock_from_file(f);
    if (sk) {
        e->dest_ip   = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        e->dest_port = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
        e->src_ip    = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        e->src_port  = BPF_CORE_READ(sk, __sk_common.skc_num);
    }

    bpf_snprintf(e->filename, sizeof(e->filename), "FD redirect: socket -> stdio", NULL, 0);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup2")
int handle_sys_enter_dup2(struct trace_event_raw_sys_enter *ctx) {
    return handle_dup_redirect((int)ctx->args[0], (int)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_dup3")
int handle_sys_enter_dup3(struct trace_event_raw_sys_enter *ctx) {
    // dup3(oldfd, newfd, flags) — same first two argument positions as dup2
    return handle_dup_redirect((int)ctx->args[0], (int)ctx->args[1]);
}

// 8. PRIVILEGE ESCALATION CHOKE POINT 
// setuid(), setgid(), setresuid(), capset(), and every other credential-
// changing syscall all funnel through this one internal function before the
// new credentials take effect. 
SEC("kprobe/commit_creds")
int BPF_KPROBE(handle_commit_creds, struct cred *new) {
    if (!new) return 0;

    unsigned int new_uid = BPF_CORE_READ(new, uid.val);
    unsigned int old_uid = (unsigned int)bpf_get_current_uid_gid(); // truncate to low 32 bits = current uid

    // commit_creds() is called constantly (every single exec(), even with no
    // privilege change involved) so we only emit when the uid is actually moving.
    if (new_uid == old_uid) return 0;

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common_context(e, TYPE_CREDS_CHANGE); // e->uid is filled in as the OLD uid by fill_common_context
    e->arg1 = new_uid;
    e->arg2 = old_uid;

    bpf_snprintf(e->filename, sizeof(e->filename), "UID change via commit_creds", NULL, 0);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 9. PROCESS INJECTION / CREDENTIAL DUMPING 
SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common_context(e, TYPE_PTRACE);
    e->arg1 = (unsigned long long)ctx->args[0];  // ptrace request (PTRACE_ATTACH, PTRACE_POKETEXT, ...)
    e->arg2 = (unsigned long long)ctx->args[1];  // target pid
    e->retval = (long long)ctx->args[1];

    bpf_snprintf(e->filename, sizeof(e->filename), "ptrace syscall", NULL, 0);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 10. SHELLCODE / W^X VIOLATION 
SEC("tracepoint/syscalls/sys_enter_mprotect")
int handle_mprotect(struct trace_event_raw_sys_enter *ctx) {
    unsigned long prot = (unsigned long)ctx->args[2];
    if ((prot & (PROT_WRITE_VAL | PROT_EXEC_VAL)) != (PROT_WRITE_VAL | PROT_EXEC_VAL)) {
        return 0; // not requesting W+X together — not interesting for this hook
    }

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common_context(e, TYPE_MPROTECT_RWX);
    e->arg1 = (unsigned long long)ctx->args[0]; // addr
    e->arg2 = (unsigned long long)prot;         // requested prot flags

    bpf_snprintf(e->filename, sizeof(e->filename), "mprotect RWX request", NULL, 0);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 11. FILELESS EXECUTION 
// memfd_create() makes an anonymous, in-memory "file" with no path on disk.
// The classic fileless-malware pattern is: memfd_create() an anonymous fd,
// write a payload into it, then execve("/proc/self/fd/N") and hence the payload
// never touches a filesystem your file-open monitoring would otherwise see.
SEC("tracepoint/syscalls/sys_enter_memfd_create")
int handle_memfd_create(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common_context(e, TYPE_MEMFD_CREATE);
    const char *name_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), name_ptr);
    e->arg1 = (unsigned long long)ctx->args[1]; // flags: MFD_CLOEXEC, MFD_ALLOW_SEALING, ...

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 12. ANTI-FORENSICS / SELF-CLEANUP 
// Deleting a file right after using it (dropped payload, cleared log) is a
// common cleanup step. 
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common_context(e, TYPE_UNLINK);
    const char *path_ptr = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), path_ptr);
    e->arg1 = (unsigned long long)ctx->args[2]; // flags (e.g. AT_REMOVEDIR)

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 13. MASQUERADING
// Renaming a dropped payload to something innocuous-looking 
SEC("tracepoint/syscalls/sys_enter_renameat2")
int handle_renameat2(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common_context(e, TYPE_RENAME);
    const char *old_ptr = (const char *)ctx->args[1];
    const char *new_ptr = (const char *)ctx->args[3];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), old_ptr);     // old path
    bpf_probe_read_user_str(&e->extra_str, sizeof(e->extra_str), new_ptr);  // new path
    e->arg1 = (unsigned long long)ctx->args[4]; // flags (RENAME_NOREPLACE, RENAME_EXCHANGE, ...)

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 14. SETUID BACKDOORS / PERMISSION TAMPERING 
// `chmod +s` on a binary is a classic simple backdoor/persistence technique
// (any user who can run it gets the file owner's privileges). arg1 carries
// the raw requested mode bits so monitor.c can check for the setuid bit.
SEC("tracepoint/syscalls/sys_enter_fchmodat")
int handle_fchmodat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common_context(e, TYPE_CHMOD);
    const char *path_ptr = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), path_ptr);
    e->arg1 = (unsigned long long)ctx->args[2]; // requested mode bits

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 15/16. KERNEL MODULE LOAD/UNLOAD (rootkit territory) 
SEC("tracepoint/syscalls/sys_enter_init_module")
int handle_init_module(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common_context(e, TYPE_MODULE_LOAD);
    e->arg1 = (unsigned long long)ctx->args[1]; // module image length in bytes
    bpf_snprintf(e->filename, sizeof(e->filename), "init_module (in-memory image)", NULL, 0);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int handle_finit_module(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common_context(e, TYPE_MODULE_LOAD);
    e->arg1 = (unsigned long long)ctx->args[0]; // fd of the .ko file
    bpf_snprintf(e->filename, sizeof(e->filename), "finit_module (from fd)", NULL, 0);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_delete_module")
int handle_delete_module(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common_context(e, TYPE_MODULE_UNLOAD);
    const char *name_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), name_ptr);
    e->arg1 = (unsigned long long)ctx->args[1]; // flags

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 17. RAW SOCKETS (packet crafting / sniffing) 
// SOCK_RAW gives a process direct access to link-layer/IP-layer packets,
// bypassing the normal TCP/UDP stack — used for packet sniffing, spoofing,
// and custom C2 protocols. Filtering for SOCK_RAW specifically (vs. logging
// every socket() call) keeps this hook's volume near zero in normal use.
SEC("tracepoint/syscalls/sys_enter_socket")
int handle_socket_create(struct trace_event_raw_sys_enter *ctx) {
    long type = (long)ctx->args[1];
    if ((type & SOCK_TYPE_MASK_VAL) != SOCK_RAW_VAL) return 0;

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common_context(e, TYPE_RAW_SOCKET);
    e->arg1 = (unsigned long long)ctx->args[0]; // address family
    e->arg2 = (unsigned long long)ctx->args[2]; // protocol

    bpf_snprintf(e->filename, sizeof(e->filename), "raw socket() created", NULL, 0);
    bpf_ringbuf_submit(e, 0);
    return 0;
}