#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

// Define event types
#define TYPE_EXEC 1
#define TYPE_OPEN 2

// Data Package Structure
struct event_t {
	unsigned int pid;
	unsigned int event_type; //1 = Exec, 2 = Open
	char comm[16]; // Linux Process names are a maximum of 16 characters
	char filename[64]; // The target bianry beign executed
};

// Ring Buffer Map Allocation
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16); // Allocating a 64KB memory buffer
} rb SEC(".maps");

// Define the raw tracepoint argument structure format used by the kernel
struct trace_event_raw_sys_enter_execve {
	unsigned long long unused;
	long id;
	unsigned long args[6]; // args[0] point to the executable path string
};

struct trace_event_raw_sys_enter_openat {
	unsigned long long unused;
	long id;
	unsigned long args[6]; // args[1] point to the executable path string for openat
};

// Attach our hook to the execve syscall entry point
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter_execve *ctx) {
	struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		return 0; // If buffer is full, drop that event safely
	}
	// bpf_get_current_pid_tgid() return 64bit number; the lower 32 bit is the pid
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->event_type = TYPE_EXEC;
	// Capturing the name of command
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	long res = bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (void *)ctx->args[0]);
	if (res < 0) {
		bpf_printk("Failed to read filename string \n");
	}

	// Submit the package down the slide to user space
	bpf_ringbuf_submit(e, 0);

	return 0;
}
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter_openat *ctx) {
	struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		return 0; // If buffer is full, drop that event safely
	}
	// bpf_get_current_pid_tgid() return 64bit number; the lower 32 bit is the pid
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->event_type = TYPE_OPEN;
	// Capturing the name of command
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	long res = bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (void *)ctx->args[1]);
	if (res < 0) {
		bpf_printk("Failed to read filename string \n");
	}

	// Submit the package down the slide to user space
	bpf_ringbuf_submit(e, 0);

	return 0;
}
