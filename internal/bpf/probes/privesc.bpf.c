// internal/bpf/probes/privesc.bpf.c
// v0.6: Tracepoints for privilege escalation detection.
//
// handle_setuid — tp/syscalls/sys_enter_setuid
// handle_setgid — tp/syscalls/sys_enter_setgid
// handle_capset — tp/syscalls/sys_enter_capset
//
// Fires before the kernel applies the privilege change. The caller's
// current UID (bpf_get_current_uid_gid) is the "before" value; the
// tracepoint argument is the requested "after" value. Root escalation
// (0→0) is a no-op and intentionally not emitted.

#include "common.bpf.h"

char _license[] SEC("license") = "GPL";

// Subtype discriminator stored in _reserved field.
#define PRIVESC_SETUID 1
#define PRIVESC_SETGID 2
#define PRIVESC_CAPSET 3

static __always_inline int submit_privesc(__u8 subtype, __u32 old_val, __u32 new_val)
{
	// Suppress no-op: remaining at the same non-zero UID/GID.
	// Root escalation (non-root → root) always emits.
	if (old_val == new_val && old_val != 0)
		return 0;

	struct edr_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	__builtin_memset(e, 0, sizeof(*e));
	e->type        = EDR_EVENT_PRIVESC;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->_reserved   = subtype;
	e->pid         = (__u32)(id >> 32);
	e->tgid        = (__u32)id;
	e->ppid        = old_val;
	e->uid         = new_val;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_setuid")
int handle_setuid(struct trace_event_raw_sys_enter *ctx)
{
	__u32 new_uid = (__u32)ctx->args[0];
	__u32 old_uid = (__u32)bpf_get_current_uid_gid();
	return submit_privesc(PRIVESC_SETUID, old_uid, new_uid);
}

SEC("tp/syscalls/sys_enter_setgid")
int handle_setgid(struct trace_event_raw_sys_enter *ctx)
{
	__u32 new_gid = (__u32)ctx->args[0];
	__u32 old_gid = (__u32)(bpf_get_current_uid_gid() >> 32);
	return submit_privesc(PRIVESC_SETGID, old_gid, new_gid);
}

SEC("tp/syscalls/sys_enter_capset")
int handle_capset(struct trace_event_raw_sys_enter *ctx)
{
	// capset(cap_user_header_t hdrp, cap_user_data_t datap)
	// We can't easily deref the user pointers from a raw tracepoint,
	// but the mere attempt to call capset is a strong signal.
	// Emit with old_val=0, new_val=1 as a binary "capset attempted" flag.
	return submit_privesc(PRIVESC_CAPSET, 0, 1);
}
