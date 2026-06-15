// EDR self-protection LSM hooks.
//
// task_kill blocks external stop signals before the kernel delivers
// them to the agent. Legal shutdown must go through /v0/shutdown;
// the kprobe selfprotect probe remains for telemetry and attacker
// response while LSM is promoted to the primary enforcement path.

#include "common.bpf.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

#define EPERM 1

static __always_inline int is_protected_signal(int sig)
{
	return sig == 1 || sig == 2 || sig == 3 || sig == 9 || sig == 15;
}

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

// int task_kill(struct task_struct *p, struct kernel_siginfo *info,
//               int sig, const struct cred *cred)
SEC("lsm/task_kill")
int BPF_PROG(lsm_task_kill, struct task_struct *p,
	     struct kernel_siginfo *info, int sig, const struct cred *cred,
	     int ret)
{
	if (ret != 0)
		return ret;

	if (!is_protected_signal(sig))
		return 0;

	if (external_to_agent(p))
		return -EPERM;

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
