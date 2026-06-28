// internal/bpf/probes/bpfop.bpf.c
// v0.7 rootkit: Tracepoint for bpf() syscall operations.
//
// handle_bpf — tp/syscalls/sys_enter_bpf
//
// Fires whenever userspace calls bpf(2). We are interested in
// operations that load, detach, or otherwise manipulate eBPF
// programs/links, because these may be used by eBPF rootkits or
// by attackers trying to disable our own probes.
//
// Output: ring buffer event of type EDR_EVENT_BPF_OP.

#include "common.bpf.h"

char _license[] SEC("license") = "GPL";

// Subset of bpf_cmd values we surface in the event filename.
// v0.16: added BPF_MAP_UPDATE_ELEM and BPF_MAP_LOOKUP_ELEM — attack
// surface for EDR self-protection bypass (zeroing agent_pid map).
#define BPF_MAP_LOOKUP_ELEM     1
#define BPF_MAP_UPDATE_ELEM     2
#define BPF_PROG_LOAD           5
#define BPF_OBJ_PIN             6
#define BPF_OBJ_GET             7
#define BPF_PROG_ATTACH         8
#define BPF_PROG_DETACH         9
#define BPF_PROG_TEST_RUN       10
#define BPF_RAW_TRACEPOINT_OPEN 24
#define BPF_BTF_LOAD            27
#define BPF_LINK_CREATE         28
#define BPF_LINK_UPDATE         29
#define BPF_LINK_DETACH         36
#define BPF_PROG_BIND_MAP       37

static __always_inline const char *cmd_name(__u32 cmd)
{
	switch (cmd) {
	case BPF_MAP_LOOKUP_ELEM: return "BPF_MAP_LOOKUP_ELEM";
	case BPF_MAP_UPDATE_ELEM: return "BPF_MAP_UPDATE_ELEM";
	case BPF_PROG_LOAD: return "BPF_PROG_LOAD";
	case BPF_OBJ_PIN: return "BPF_OBJ_PIN";
	case BPF_OBJ_GET: return "BPF_OBJ_GET";
	case BPF_PROG_ATTACH: return "BPF_PROG_ATTACH";
	case BPF_PROG_DETACH: return "BPF_PROG_DETACH";
	case BPF_PROG_TEST_RUN: return "BPF_PROG_TEST_RUN";
	case BPF_RAW_TRACEPOINT_OPEN: return "BPF_RAW_TRACEPOINT_OPEN";
	case BPF_BTF_LOAD: return "BPF_BTF_LOAD";
	case BPF_LINK_CREATE: return "BPF_LINK_CREATE";
	case BPF_LINK_UPDATE: return "BPF_LINK_UPDATE";
	case BPF_LINK_DETACH: return "BPF_LINK_DETACH";
	case BPF_PROG_BIND_MAP: return "BPF_PROG_BIND_MAP";
	default: return "BPF_OP";
	}
}

SEC("tp/syscalls/sys_enter_bpf")
int handle_bpf(struct trace_event_raw_sys_enter *ctx)
{
	__u32 cmd = (__u32)ctx->args[0];

	// Only emit for commands that are security-relevant for rootkit
	// detection or self-protection. Skip benign queries.
	switch (cmd) {
	case BPF_MAP_LOOKUP_ELEM:
	case BPF_MAP_UPDATE_ELEM:
	case BPF_PROG_LOAD:
	case BPF_OBJ_PIN:
	case BPF_OBJ_GET:
	case BPF_PROG_ATTACH:
	case BPF_PROG_DETACH:
	case BPF_RAW_TRACEPOINT_OPEN:
	case BPF_BTF_LOAD:
	case BPF_LINK_CREATE:
	case BPF_LINK_UPDATE:
	case BPF_LINK_DETACH:
	case BPF_PROG_BIND_MAP:
		break;
	default:
		return 0;
	}

	// v0.16: for map read/write operations, skip events from the EDR
	// agent itself — those are normal self-maintenance. We only care
	// about external processes (attacker tools like bpftool).
	if (cmd == BPF_MAP_UPDATE_ELEM || cmd == BPF_MAP_LOOKUP_ELEM) {
		char comm[16];
		bpf_get_current_comm(&comm, sizeof(comm));
		// Skip EDR agent self-operations (policy reload writes blacklists, etc.)
		if (__builtin_memcmp(comm, "edr-agent", 9) == 0)
			return 0;
		// Also skip bpftool used by ourselves during controlled maintenance
		// (the userspace policy engine can still alert on bpftool usage via
		// process-access monitoring).
	}

	struct edr_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	__builtin_memset(e, 0, sizeof(*e));
	e->type = EDR_EVENT_BPF_OP;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->_reserved = cmd;
	e->pid = (__u32)(id >> 32);
	e->tgid = (__u32)id;
	e->uid = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	const char *name = cmd_name(cmd);
	// cmd_name returns a literal from the ELF; bpf_probe_read_kernel_str
	// copies it into the event buffer.
	(void)bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), name);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
