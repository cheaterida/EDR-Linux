// EDR self-protection LSM hooks (v0.9 hardened).
//
// task_kill blocks ALL external signals to the agent — no longer
// limited to {1,2,3,9,15}. SIGSTOP(19) and SIGCONT(18) are now
// included. The kprobe selfprotect probe remains for telemetry
// and attacker response; LSM is the primary enforcement path.
//
// v0.9: ringbuf audit output added — every LSM denial is now
// recorded as EDR_EVENT_SELFPROTECT for forensics.

#include "common.bpf.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

#define EPERM 1

static __always_inline int is_agent_task(struct task_struct *task, __u32 agent)
{
	__u32 pid = BPF_CORE_READ(task, pid);
	__u32 tgid = BPF_CORE_READ(task, tgid);
	return pid == agent || tgid == agent;
}

static __always_inline int external_to_agent(struct task_struct *target)
{
	__u32 key = 0;
	__u32 *agent = bpf_map_lookup_elem(&agent_pid, &key);
	if (!agent)
		return 0;

	if (!is_agent_task(target, *agent))
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	__u32 current_tgid = id >> 32;
	if (current_tgid == *agent)
		return 0;

	return 1;
}

static __always_inline void emit_lsm_audit(__u32 target_pid, __u32 sig)
{
	struct edr_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;

	__u64 id = bpf_get_current_pid_tgid();
	__builtin_memset(e, 0, sizeof(*e));
	e->type = EDR_EVENT_SELFPROTECT;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid  = (__u32)(id >> 32);
	e->ppid = target_pid;
	e->tgid = (__u32)id;
	e->uid  = (__u32)bpf_get_current_uid_gid();
	e->_reserved = sig; // which signal was blocked
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__builtin_memcpy(e->filename, "lsm_task_kill", 14);

	bpf_ringbuf_submit(e, 0);
}

// int task_kill(struct task_struct *p, struct kernel_siginfo *info,
//               int sig, const struct cred *cred)
SEC("lsm/task_kill")
int BPF_PROG(lsm_task_kill, struct task_struct *p,
	     struct kernel_siginfo *info, int sig, const struct cred *cred,
	     int ret)
{
	if (ret != 0)
		return ret;

	// v0.9: NO signal white-list. All external signals are blocked.
	if (external_to_agent(p)) {
		emit_lsm_audit(BPF_CORE_READ(p, pid), sig);
		return -EPERM;
	}

	return 0;
}

// int ptrace_access_check(struct task_struct *child, unsigned int mode)
SEC("lsm/ptrace_access_check")
int BPF_PROG(lsm_ptrace_access_check, struct task_struct *child,
	     unsigned int mode, int ret)
{
	if (ret != 0)
		return ret;

	if (external_to_agent(child))
		return -EPERM;

	return 0;
}
