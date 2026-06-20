// internal/bpf/probes/module.bpf.c
// v0.7 rootkit: Tracepoints for kernel module load/unload detection.
//
// handle_init_module  — tp/syscalls/sys_enter_init_module
// handle_finit_module — tp/syscalls/sys_enter_finit_module
// handle_delete_module — tp/syscalls/sys_enter_delete_module
//
// Emits ring buffer events of type EDR_EVENT_MODULE_LOAD /
// EDR_EVENT_MODULE_UNLOAD. The module name (or "finit_module" when
// loaded via fd) is copied into filename; flags / fd are stored in
// _reserved.

#include "common.bpf.h"

char _license[] SEC("license") = "GPL";

// Subtypes stored in _reserved to distinguish load paths.
#define MODULE_INIT  1
#define MODULE_FINIT 2
#define MODULE_DELETE 3

static __always_inline int submit_module_event(__u8 type, __u8 subtype,
				       const char *name, __u32 flags_or_fd)
{
	struct edr_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	__builtin_memset(e, 0, sizeof(*e));
	e->type = type;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->_reserved = ((__u32)subtype << 16) | (flags_or_fd & 0xFFFF);
	e->pid = (__u32)(id >> 32);
	e->tgid = (__u32)id;
	e->uid = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	if (name) {
		// Best-effort read of the module name. We don't fail the
		// event if the userspace string is unreadable — the probe
		// itself firing is the detection signal.
		(void)bpf_probe_read_user_str(e->filename, sizeof(e->filename), name);
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_init_module")
int handle_init_module(struct trace_event_raw_sys_enter *ctx)
{
	const char *name = (const char *)ctx->args[2]; // param_values
	__u32 len = (__u32)ctx->args[1];
	return submit_module_event(EDR_EVENT_MODULE_LOAD, MODULE_INIT, name, len);
}

SEC("tp/syscalls/sys_enter_finit_module")
int handle_finit_module(struct trace_event_raw_sys_enter *ctx)
{
	__u32 fd = (__u32)ctx->args[0];
	// param_values is args[1]; flags is args[2]. We store fd in the
	// lower 16 bits and flags in _reserved too would overflow the
	// 16-bit space, so we keep fd only and a sentinel filename.
	return submit_module_event(EDR_EVENT_MODULE_LOAD, MODULE_FINIT,
				   "finit_module", fd);
}

SEC("tp/syscalls/sys_enter_delete_module")
int handle_delete_module(struct trace_event_raw_sys_enter *ctx)
{
	const char *name = (const char *)ctx->args[0];
	__u32 flags = (__u32)ctx->args[1];
	return submit_module_event(EDR_EVENT_MODULE_UNLOAD, MODULE_DELETE,
				   name, flags);
}
