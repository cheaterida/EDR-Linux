// internal/bpf/probes/instrument.bpf.c
// Binary instrumentation detection via mmap monitoring.
//
// Hooks sys_enter_mmap to detect suspicious shared library mappings.
// When a process maps a file with MAP_PRIVATE (typical for shared
// libraries), emits an event. The Go side scans /proc/pid/maps for
// known instrumentation artifacts (frida-agent, linjector, etc.).
//
// Per-pid rate limiting: one event per 5 seconds per process to
// prevent mmap flood DoS.
//
// Output: ring buffer event with type=EDR_EVENT_INSTRUMENT.

#include "common.bpf.h"

char _license[] SEC("license") = "GPL";

// mmap flags (from linux/mman.h)
#define MAP_PRIVATE   0x02
#define MAP_ANONYMOUS 0x20
#define MAP_FIXED     0x10

// Rate limit: 5 seconds per pid (in nanoseconds)
#define RATE_LIMIT_NS 5000000000ULL

// Per-pid last event timestamp for rate limiting
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);   // pid
	__type(value, __u64);  // timestamp_ns
} pid_last_event SEC(".maps") __attribute__((weak));

// __x64_sys_mmap(struct pt_regs *regs)
// regs->di = addr, regs->si = len, regs->dx = prot,
// regs->r10 = flags, regs->r8 = fd, regs->r9 = off
SEC("kprobe/__x64_sys_mmap")
int handle_instrument(struct pt_regs *ctx)
{
	struct pt_regs *kregs = (struct pt_regs *)ctx->di;
	__u64 flags;
	__u64 fd;

	bpf_probe_read_kernel(&flags, sizeof(flags), &kregs->r10);
	bpf_probe_read_kernel(&fd, sizeof(fd), &kregs->r8);

	// Only interested in file-backed private mappings (shared library loading)
	// Skip anonymous mappings and shared mappings
	if (flags & MAP_ANONYMOUS)
		return 0;
	if (!(flags & MAP_PRIVATE))
		return 0;
	// Skip invalid fd
	if ((int)fd < 0)
		return 0;

	// Get caller identity
	__u64 id = bpf_get_current_pid_tgid();
	__u32 pid = id >> 32;

	// Rate limit: skip if last event for this pid was within RATE_LIMIT_NS
	__u64 now = bpf_ktime_get_ns();
	__u64 *last_ts = bpf_map_lookup_elem(&pid_last_event, &pid);
	if (last_ts) {
		if (now - *last_ts < RATE_LIMIT_NS)
			return 0;
	}

	struct edr_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	// Update rate limit timestamp
	bpf_map_update_elem(&pid_last_event, &pid, &now, BPF_ANY);

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EDR_EVENT_INSTRUMENT;
	e->timestamp_ns = now;
	e->pid = pid;
	e->tgid = (__u32)id;
	e->uid = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// Store fd in _reserved for Go-side /proc/pid/fd resolution
	e->_reserved = (__u32)fd;
	__builtin_memcpy(e->filename, "mmap_file", 10);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
