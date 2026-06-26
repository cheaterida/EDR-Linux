// internal/bpf/probes/lsm_bpf_guard.bpf.c
// v0.9: LSM fmod_ret guards for BPF self-protection.
//
// security_bpf — intercepts BPF_LINK_DETACH, BPF_PROG_DETACH,
// BPF_MAP_UPDATE_ELEM (blocklist operations) from non-agent callers.
// fmod_ret overrides the return value to -EPERM, making the kernel
// deny the operation at the LSM layer. This is the primary enforcement
// layer; the kprobe bpf_guard probe provides telemetry.
//
// Self-exclusion uses agent_pid map (PID match), not comm — comm
// can be forged via exec -a "edr-agent".
//
// Why LSM and not kprobe: kprobe override (bpf_override_return) only
// works on syscall entry, not inside the BPF subsystem itself. LSM
// hooks intercept at the permission-check level which the kernel
// always consults before taking action.

#include "common.bpf.h"
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define EPERM               1
#define BPF_MAP_UPDATE_ELEM 2
#define BPF_PROG_DETACH     8
#define BPF_LINK_DETACH     14

static __always_inline int is_agent(void)
{
	__u32 key = 0;
	__u32 *agent = bpf_map_lookup_elem(&agent_pid, &key);
	if (!agent)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	return (__u32)(id >> 32) == *agent;
}

static __always_inline void emit_lsm_bpf_audit(__u32 cmd)
{
	struct edr_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;

	__u64 id = bpf_get_current_pid_tgid();
	__builtin_memset(e, 0, sizeof(*e));
	e->type = EDR_EVENT_SELFPROTECT;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid  = (__u32)(id >> 32);
	e->tgid = (__u32)id;
	e->uid  = (__u32)bpf_get_current_uid_gid();
	e->_reserved = cmd;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__builtin_memcpy(e->filename, "lsm_bpf_guard", 14);

	bpf_ringbuf_submit(e, 0);
}

// int security_bpf(int cmd, union bpf_attr *attr, unsigned int size)
//
// Blocks destructive BPF operations from non-agent callers:
//   BPF_PROG_DETACH  — prevent unloading EDR's BPF programs
//   BPF_LINK_DETACH  — prevent breaking EDR's LSM/kprobe links
//   BPF_MAP_UPDATE_ELEM — prevent zeroing agent_pid or tampering maps
//
// BPF_MAP_DELETE_ELEM would also be useful, but bpf_guard.bpf.c
// does not handle it; adding it here would broaden coverage without
// requiring the kprobe probe to be updated.
SEC("fmod_ret/security_bpf")
int BPF_PROG(lsm_bpf_guard, int cmd, union bpf_attr *attr,
	     unsigned int size, int ret)
{
	if (ret != 0)
		return ret;

	if (is_agent())
		return 0;

	switch (cmd) {
	case BPF_PROG_DETACH:
	case BPF_LINK_DETACH:
	case BPF_MAP_UPDATE_ELEM:
		emit_lsm_bpf_audit(cmd);
		return -EPERM;
	}

	return 0;
}
