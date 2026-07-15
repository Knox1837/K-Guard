#define _POSIX_C_SOURCE 199309L
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>          
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <time.h>
#include "kguard.skel.h"

#define TYPE_EXEC         1
#define TYPE_FORK         2
#define TYPE_EXIT         3
#define TYPE_OPEN         4
#define TYPE_TCP_CONNECT  5
#define TYPE_TCP_CLOSE    6

#define TYPE_TCP_ACCEPT    7
#define TYPE_DUP_REDIRECT  8
#define TYPE_CREDS_CHANGE  9
#define TYPE_PTRACE        10
#define TYPE_MPROTECT_RWX  11
#define TYPE_MEMFD_CREATE  12
#define TYPE_UNLINK        13
#define TYPE_RENAME        14
#define TYPE_CHMOD         15
#define TYPE_MODULE_LOAD   16
#define TYPE_MODULE_UNLOAD 17
#define TYPE_RAW_SOCKET    18

#define PID_HASH_SIZE 1024

// Per-process degree/feature tracking Keyed by (pid, start_time_ns) together, NOT pid alone. PIDs can be reused by the kernel, and start_time_ns is a unique identifier 

struct pid_degree_t {
    unsigned int pid;
    unsigned long long start_time_ns;
    int in_degree;
    int out_degree;
    float max_len;
    float max_entropy;
    int contains_sensitive;
    struct pid_degree_t *next;
};

static struct pid_degree_t *pid_table[PID_HASH_SIZE] = {NULL};

static void reset_entry(struct pid_degree_t *e, unsigned int pid, unsigned long long start_time_ns) {
    e->pid = pid;
    e->start_time_ns = start_time_ns;
    e->in_degree = 0;
    e->out_degree = 0;
    e->max_len = 0.0f;
    e->max_entropy = 0.0f;
    e->contains_sensitive = 0;
}

// Find the entry for (pid, start_time_ns). If `pid` exists in the table but belongs to a DIFFERENT start_time_ns, the PID has been reused by a new process — the stale entry is reset in place rather than aliased onto.
static struct pid_degree_t* get_or_create_pid_entry(unsigned int pid, unsigned long long start_time_ns) {
    unsigned int slot = pid % PID_HASH_SIZE;
    struct pid_degree_t *curr = pid_table[slot];

    while (curr) {
        if (curr->pid == pid) {
            long long diff = (long long)start_time_ns - (long long)curr->start_time_ns;
            if (curr->start_time_ns != start_time_ns && (diff > 2000000000LL || diff < 0)) { // if the start_time_ns is different and the difference is more than 2 seconds or negative, we assume the PID has been reused by a new process
                reset_entry(curr, pid, start_time_ns);
            }
            else {
                curr->start_time_ns = start_time_ns; //promote to true start time
            }
            return curr;
        }
        curr = curr->next;
    }

    struct pid_degree_t *new_entry = calloc(1, sizeof(struct pid_degree_t));
    if (!new_entry) return NULL;

    reset_entry(new_entry, pid, start_time_ns);
    new_entry->next = pid_table[slot];
    pid_table[slot] = new_entry;
    return new_entry;
}

// Shannon entropy over the raw bytes of a string: used to flag packed/encrypted/randomized looking paths and arguments
static double shannon_entropy(const char *s) {
    int counts[256] = {0};
    int n = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        counts[*p]++;
        n++;
    }
    if (n == 0) return 0.0;
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0) continue;
        double p = (double)counts[i] / n;
        entropy -= p * log2(p);
    }
    return entropy;
}

static const char *SENSITIVE_KEYWORDS[] = {"shadow", "passwd", "secret", "root", ".ssh", "id_rsa", "id_dsa", "etc/hosts", "bash_history", "config"}; //some sensitive keywords to check for in strings
static int is_sensitive_str(const char *s) {
    for (size_t i = 0; i < sizeof(SENSITIVE_KEYWORDS) / sizeof(SENSITIVE_KEYWORDS[0]); i++) {
        if (strstr(s, SENSITIVE_KEYWORDS[i])) return 1;
    }
    return 0;
}

// Is dest_ip inside a private/RFC1918 range (10/8, 172.16/12, 192.168/16, 127/8 loopback)?
static int is_private_ip(unsigned int addr_be) {
    unsigned int h = ntohl(addr_be); // convert to host order
    unsigned char b0 = (h >> 24) & 0xFF;
    unsigned char b1 = (h >> 16) & 0xFF;
    if (b0 == 10) return 1;                        // 10.0.0.0/8
    if (b0 == 172 && b1 >= 16 && b1 <= 31) return 1; // 172.16.0.0/12
    if (b0 == 192 && b1 == 168) return 1;            // 192.168.0.0/16
    if (b0 == 127) return 1;                         // 127.0.0.0/8 loopback
    return 0;
}

// Is dest_port a common well-known port (HTTP, HTTPS, SSH, DNS, FTP, SMTP, NTP, IMAP, POP3, etc.)? 
// Used to flag connections that are more likely to be benign.
static int is_common_port(unsigned short port) {
    switch (port) {
        case 80: case 443: case 22: case 53: case 21:
        case 25: case 123: case 993: case 995: case 587:
            return 1;
        default:
            return 0;
    }
}

static void update_node_features(struct pid_degree_t *n, const char *target_str) { 
    if (!n || !target_str) return;

    float len = (float)strlen(target_str);
    if (len > n->max_len) n->max_len = len;

    float ent = (float)shannon_entropy(target_str);
    if (ent > n->max_entropy) n->max_entropy = ent;

    if (!n->contains_sensitive && is_sensitive_str(target_str)) {
        n->contains_sensitive = 1;
    }
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

    unsigned int src_ip;
    unsigned short src_port;
    unsigned char protocol;
    unsigned long long bytes_sent;
    unsigned long long bytes_recv;
    unsigned long long duration_ns;

    unsigned long long arg1;
    unsigned long long arg2;
    char extra_str[128];
};

FILE *jsonl_file = NULL;

void generate_session_id(char *buf) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        sprintf(buf, "fallback-id-%d", getpid());
        return;
    }

    unsigned char random_data[16];
    // Check the return value of read()
    ssize_t bytes_read = read(fd, random_data, 16);
    close(fd);

    if (bytes_read != 16) {
        // If we didn't get 16 bytes, fallback to something safe
        sprintf(buf, "error-id-%d", getpid());
        return;
    }

    for (int i = 0; i < 16; i++) {
        sprintf(buf + (i * 2), "%02x", random_data[i]);
    }
    buf[32] = '\0';
}

static void read_cmdline(pid_t pid, char *buf, size_t size)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        buf[0] = '\0';
        return;
    }

    size_t n = fread(buf, 1, size - 1, fp);
    fclose(fp);

    buf[n] = '\0';

    /* /proc/<pid>/cmdline separates args with '\0' */
    for (size_t i = 0; i < n; i++) {
        if (buf[i] == '\0')
            buf[i] = ' ';
    }
}

// This function is used to escape special characters in strings before writing them to JSONL files. 
// It handles quotes, backslashes, newlines, and tabs, while dropping other control characters to ensure valid JSON output.
static const char *json_escape(const char *in) {
    static char bufs[6][300];
    static int slot = 0;
    char *out = bufs[slot];
    slot = (slot + 1) % 6;

    size_t j = 0;
    for (size_t i = 0; in[i] != '\0' && j < sizeof(bufs[0]) - 2; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') {
            out[j++] = '\\';
            out[j++] = (char)c;
        } else if (c == '\n') {
            out[j++] = '\\'; out[j++] = 'n';
        } else if (c == '\t') {
            out[j++] = '\\'; out[j++] = 't';
        } else if (c < 0x20) {
            continue; // drop other control chars rather than emit invalid JSON
        } else {
            out[j++] = (char)c;
        }
    }
    out[j] = '\0';
    return out;
}

static int handle_event(void *ctx, void *data, size_t sz) {
    struct event_t *e = data;
    char ip_str[INET_ADDRSTRLEN] = "";      // dest IP, human-readable, left intentionally empty for non-network events
    char src_ip_str[INET_ADDRSTRLEN] = "";  // source IP, only meaningful for TYPE_TCP_CLOSE, left intentionally empty for non-network events

    if (e->event_type == TYPE_TCP_CONNECT || e->event_type == TYPE_TCP_CLOSE ||
        e->event_type == TYPE_TCP_ACCEPT  || e->event_type == TYPE_DUP_REDIRECT) {
        struct in_addr addr = { .s_addr = e->dest_ip };
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
    }
    if (e->event_type == TYPE_TCP_CLOSE || e->event_type == TYPE_TCP_ACCEPT ||
        e->event_type == TYPE_DUP_REDIRECT) {
        struct in_addr src_addr = { .s_addr = e->src_ip };
        inet_ntop(AF_INET, &src_addr, src_ip_str, sizeof(src_ip_str));
    }

    struct pid_degree_t *proc_stats = get_or_create_pid_entry(e->pid, e->start_time_ns);

    switch (e->event_type) {
        case TYPE_EXEC:
            if (proc_stats) {
                proc_stats->out_degree++;
                update_node_features(proc_stats, e->filename);
                if (e->extra_str[0] != '\0') { 
                    update_node_features(proc_stats, e->extra_str);
                }
                if (e->extra_str[64] != '\0') {
                    update_node_features(proc_stats, e->extra_str + 64);
                }
            }
            break;
        case TYPE_OPEN:
            if (proc_stats) {
                proc_stats->out_degree++;
                update_node_features(proc_stats, e->filename);
            }
            break;
        case TYPE_FORK: {
            unsigned int child_pid = (unsigned int)e->retval;
            // char child_id[64]; //childs true start time is not knowable as kernel only reports it later so we use a placeholder from parents start time(ns)
            
            // snprintf(child_id, sizeof(child_id), "proc_%u_%llu", child_pid, e->start_time_ns);

            if (proc_stats) {
                proc_stats->out_degree++;
                // update_node_features(proc_stats, child_id); //this can cause highnanosecond strings from polluting max_entropy and max_len
            }
            struct pid_degree_t *child_stats = get_or_create_pid_entry(child_pid, e->start_time_ns);
            if (child_stats) child_stats->in_degree++;
            break;
        }
        case TYPE_EXIT:
            break;
        case TYPE_TCP_CLOSE:
            // intentionally no degree update as TYPE_TCP_CONNECT already
            // counted this edge when the connection opened. TCP_CLOSE just caries the metadata
            break;
        case TYPE_TCP_CONNECT:
            if (proc_stats) {
                char target_buf[INET_ADDRSTRLEN + 8];
                snprintf(target_buf, sizeof(target_buf), "%s:%u", ip_str, e->dest_port);
                proc_stats->out_degree++;
                update_node_features(proc_stats, target_buf);
            }
            break;
        case TYPE_TCP_ACCEPT:
            // inbound connection counts as an in_degree edge (someone
            // connected TO this process), mirroring how TYPE_TCP_CONNECT
            // counts an out_degree edge for outbound connections.
            if (proc_stats) {
                char target_buf[INET_ADDRSTRLEN + 8];
                snprintf(target_buf, sizeof(target_buf), "%s:%u", ip_str, e->dest_port);
                proc_stats->in_degree++;
                update_node_features(proc_stats, target_buf);
            }
            break;
        case TYPE_DUP_REDIRECT:
        case TYPE_CREDS_CHANGE:
        case TYPE_PTRACE:
        case TYPE_MPROTECT_RWX:
        case TYPE_MEMFD_CREATE:
        case TYPE_UNLINK:
        case TYPE_RENAME:
        case TYPE_CHMOD:
        case TYPE_MODULE_LOAD:
        case TYPE_MODULE_UNLOAD:
        case TYPE_RAW_SOCKET:
            // these events are security signals, not process/
            // file/network graph edges hence there is intentionally no degree update.
            // They still get their own jsonl records though.
            break;
        default:
            break;
    }

    int out_degree = proc_stats ? proc_stats->out_degree : 0;
    int in_degree = proc_stats ? proc_stats->in_degree : 0;
    int connections = out_degree + in_degree;
    float max_len = proc_stats ? proc_stats->max_len : 0.0f;
    float max_entropy = proc_stats ? proc_stats->max_entropy : 0.0f;
    int contains_sensitive = proc_stats ? proc_stats->contains_sensitive : 0;

    // Get wall time as a float (seconds since epoch)
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    double wall_time = ts.tv_sec + (ts.tv_nsec / 1e9);
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
        case TYPE_TCP_CLOSE:
            printf("\"event\": \"NET_CLOSE\", \"pid\": %u, \"comm\": \"%s\", \"src\": \"%s:%u\", "
                   "\"dest_ip\": \"%s\", \"dest_port\": %u, "
                   "\"bytes_sent\": %llu, \"bytes_recv\": %llu, \"duration_ns\": %llu, \"duration_ms\": %.3f}\n",
                   e->pid, e->comm, src_ip_str, e->src_port, ip_str, e->dest_port,
                   e->bytes_sent, e->bytes_recv, e->duration_ns, e->duration_ns / 1e6);
            break;
        default:
            printf("\"event\": \"UNKNOWN\"}\n");
            break;
    }
    fflush(stdout);
    
    const char *event_str = "UNKNOWN";
    switch (e->event_type) {
        case TYPE_EXEC:        event_str = "EXEC";        break;
        case TYPE_FORK:        event_str = "FORK";        break;
        case TYPE_EXIT:        event_str = "EXIT";        break;
        case TYPE_OPEN:        event_str = "OPEN";        break;
        case TYPE_TCP_CONNECT: event_str = "NET_CONNECT"; break;
        case TYPE_TCP_CLOSE:   event_str = "NET_CLOSE";   break;
        case TYPE_TCP_ACCEPT:  event_str = "NET_ACCEPT";  break;
        case TYPE_DUP_REDIRECT: event_str = "FD_REDIRECT"; break;
        case TYPE_CREDS_CHANGE: event_str = "CREDS_CHANGE"; break;
        case TYPE_PTRACE:       event_str = "PTRACE";       break;
        case TYPE_MPROTECT_RWX: event_str = "MPROTECT_RWX"; break;
        case TYPE_MEMFD_CREATE: event_str = "MEMFD_CREATE"; break;
        case TYPE_UNLINK:       event_str = "UNLINK";       break;
        case TYPE_RENAME:       event_str = "RENAME";       break;
        case TYPE_CHMOD:        event_str = "CHMOD";        break;
        case TYPE_MODULE_LOAD:  event_str = "MODULE_LOAD";  break;
        case TYPE_MODULE_UNLOAD: event_str = "MODULE_UNLOAD"; break;
        case TYPE_RAW_SOCKET:   event_str = "RAW_SOCKET";   break;
    }

    // This is just logging to stdout for human inspection, not the ML model. The ML model gets its own JSONL records below.
    // printf("[%s] {\"timestamp_ns\": %llu, \"pid\": %u, \"comm\": \"%s\" \n", event_str, e->timestamp_ns, e->pid, e->comm);
    // fflush(stdout);

    const char *status = "RUNNING"; // Default baseline
    switch (e->event_type) {
        case TYPE_EXEC:        status = "EXECUTED"; break;
        case TYPE_FORK:        status = "FORKED";   break;
        case TYPE_EXIT:        status = "EXITED";   break;
        case TYPE_TCP_CONNECT: status = "NETWORK";  break;
        case TYPE_TCP_CLOSE:   status = "NET_CLOSED"; break;
        case TYPE_TCP_ACCEPT:  status = "NET_INBOUND"; break;
        case TYPE_DUP_REDIRECT:
        case TYPE_CREDS_CHANGE:
        case TYPE_PTRACE:
        case TYPE_MPROTECT_RWX:
        case TYPE_MEMFD_CREATE:
        case TYPE_UNLINK:
        case TYPE_RENAME:
        case TYPE_CHMOD:
        case TYPE_MODULE_LOAD:
        case TYPE_MODULE_UNLOAD:
        case TYPE_RAW_SOCKET:
            status = "SECURITY_EVENT";
            break;
    }


    unsigned long long total_bytes = e->bytes_sent + e->bytes_recv;
    double duration_ms = e->duration_ns / 1e6;
    double duration_s  = e->duration_ns / 1e9;

    // Ratio of bytes sent to bytes received. 
   double send_recv_ratio = (e->bytes_recv > 0)
        ? (double)e->bytes_sent / (double)e->bytes_recv
        : (e->bytes_sent > 0 ? 999.0 : 0.0);
    int dest_is_private = is_private_ip(e->dest_ip);
    int dest_is_common_port = is_common_port(e->dest_port);

    const char *label = "BENIGN"; // Default assumption

    if (contains_sensitive && max_entropy > 5.0) { //assumption of higher risk criterion
        label = "SUSPECT_OBFUSCATION";
    }
    else if (strcmp(e->comm, "nc") == 0 || strcmp(e->comm, "ncat") == 0) {//common netcat binaries
        label = "RISK_REVERSE_SHELL";
    }
    else if (e->event_type == TYPE_TCP_CLOSE) {
        int shell_like_comm =
            strcmp(e->comm, "sh") == 0   || strcmp(e->comm, "bash") == 0 ||
            strcmp(e->comm, "dash") == 0 || strcmp(e->comm, "zsh") == 0 ||
            strcmp(e->comm, "socat") == 0;

        if (shell_like_comm && !dest_is_common_port) {
            // A shell binary itself holding a live socket to a non-standard
            // port is the single strongest reverse-shell signal there is
            label = "RISK_REVERSE_SHELL";
        }
        else if (!dest_is_common_port && !dest_is_private && duration_s > 30.0 && total_bytes > 0) {
            // Long-lived connection out to a public IP on an unusual port:
            // classic C2 beacon / lingering shell shape, even if the comm
            // name looks innocuous (attackers rarely leave it named "nc").
            label = "SUSPECT_C2_BEACON";
        }
    }
    else if (e->event_type == TYPE_DUP_REDIRECT) {
        // the kernel side only ever emits this event when it already
        // confirmed a live socket got dup'd onto fd 0/1/2
        label = "CRITICAL_REVERSE_SHELL_FD_REDIRECT";
    }
    else if (e->event_type == TYPE_CREDS_CHANGE) {
        // arg1 = new uid, arg2 = old uid (see handle_commit_creds in kguard.bpf.c)
        if (e->arg1 == 0 && e->arg2 != 0) {
            label = "RISK_PRIV_ESCALATION_TO_ROOT";
        } else {
            label = "INFO_UID_CHANGE";
        }
    }
    else if (e->event_type == TYPE_PTRACE) {
        // Not every ptrace() call is malicious (debuggers use it constantly),
        // so this is flagged as SUSPECT rather than RISK/CRITICAL — treat it
        // as a feature for the model rather than a verdict on its own.
        label = "SUSPECT_PTRACE";
    }
    else if (e->event_type == TYPE_MPROTECT_RWX) {
        // Kernel side already filtered for the W+X combination specifically.
        label = "SUSPECT_RWX_MPROTECT";
    }
    else if (e->event_type == TYPE_MEMFD_CREATE) {
        label = "SUSPECT_FILELESS_EXEC_PREP";
    }
    else if (e->event_type == TYPE_UNLINK) {
        // A plain delete is mostly noise but a delete of something that looked
        // sensitive (matched by the same keyword scan used for OPEN/EXEC
        // targets) is a much stronger anti-forensics signal.
        label = contains_sensitive ? "SUSPECT_ANTI_FORENSICS" : "INFO_FILE_DELETE";
    }
    else if (e->event_type == TYPE_RENAME) {
        label = "INFO_FILE_RENAME";
    }
    else if (e->event_type == TYPE_CHMOD) {
        // setuid (04000) / setgid (02000) bits being added is the actual
        // backdoor pattern whereas a plain permission tweak isn't.
        unsigned long long mode = e->arg1;
        label = (mode & 06000) ? "RISK_SETUID_BIT_SET" : "INFO_CHMOD";
    }
    else if (e->event_type == TYPE_MODULE_LOAD) {
        // Loading kernel code is high-severity basically unconditionally hence
        // no further heuristic filtering applied here on purpose.
        label = "RISK_KERNEL_MODULE_LOAD";
    }
    else if (e->event_type == TYPE_MODULE_UNLOAD) {
        label = "RISK_KERNEL_MODULE_UNLOAD";
    }
    else if (e->event_type == TYPE_RAW_SOCKET) {
        label = "SUSPECT_RAW_SOCKET";
    }
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

    // Write the JSONL record to the file if it's open
    if (jsonl_file) {
        // extra_str holds two fixed 64-byte argv slots ONLY for TYPE_EXEC
        // (see handle_execve in kguard.bpf.c) — split them out explicitly
        // here rather than only exposing the combined raw buffer, which
        // would silently truncate at the first NUL and lose argv[2].
        char argv1[65] = {0};
        char argv2[65] = {0};
        if (e->event_type == TYPE_EXEC) {
            memcpy(argv1, e->extra_str, 64);
            argv1[64] = '\0';
            memcpy(argv2, e->extra_str + 64, 64);
            argv2[64] = '\0';
        }

        fprintf(jsonl_file,
            "{\"timestamp_ns\": %llu, \"wall_time\": %.6f, \"node_id\": \"proc_%u_%llu\", "
            "\"event\": \"%s\", \"event_type_id\": %u, "
            "\"pid\": %u, \"ppid\": %u, \"uid\": %u, \"gid\": %u, \"comm\": \"%s\", "
            "\"retval\": %lld, \"filename\": \"%s\", \"extra_str\": \"%s\", "
            "\"argv1\": \"%s\", \"argv2\": \"%s\", \"arg1\": %llu, \"arg2\": %llu, "
            "\"protocol\": %u, \"src_ip\": \"%s\", \"src_port\": %u, \"dest_ip\": \"%s\", \"dest_port\": %u, "
            "\"dest_is_private\": %d, \"dest_is_common_port\": %d, "
            "\"bytes_sent\": %llu, \"bytes_recv\": %llu, \"total_bytes\": %llu, \"send_recv_ratio\": %.4f, "
            "\"duration_ns\": %llu, \"duration_ms\": %.3f, "
            "\"out_degree\": %d, \"in_degree\": %d, \"connections\": %d, "
            "\"max_len\": %.2f, \"max_entropy\": %.2f, \"contains_sensitive\": %d, "
            "\"status\": \"%s\", \"label\": \"%s\"}\n",
            e->timestamp_ns, wall_time, e->pid, e->start_time_ns,
            event_str, e->event_type,
            e->pid, e->ppid, e->uid, e->gid, json_escape(e->comm),
            e->retval, json_escape(e->filename), json_escape(e->extra_str),
            json_escape(argv1), json_escape(argv2), e->arg1, e->arg2,
            e->protocol, src_ip_str, e->src_port, ip_str, e->dest_port,
            dest_is_private, dest_is_common_port,
            e->bytes_sent, e->bytes_recv, total_bytes, send_recv_ratio,
            e->duration_ns, duration_ms,
            out_degree, in_degree, connections,
            max_len, max_entropy, contains_sensitive,
            status, label
        );
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
    snprintf(filepath, sizeof(filepath), "./logs/session_%04d_%02d_%02d_%02d_%02d_%02d.jsonl",
             time_info->tm_year + 1900,
             time_info->tm_mon + 1,
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