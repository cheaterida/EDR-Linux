// internal/bpf/probes/selfprotect.bpf.c
// Kprobes for EDR agent self-protection.
//
// handle_kill   — kprobe:__x64_sys_kill    (struct pt_regs *regs)
// handle_tgkill — kprobe:__x64_sys_tgkill  (struct pt_regs *regs)
// handle_ptrace — kprobe:__x64_sys_ptrace  (struct pt_regs *regs)
// handle_pidfd_send_signal — kprobe:__x64_sys_pidfd_send_signal
//
// With CONFIG_ARCH_HAS_SYSCALL_WRAPPER (default on kernel 6.x),
// each __x64_sys_* entry takes a *single* argument: a pointer to
// the CPU registers saved on the kernel stack.  The real syscall
// arguments are inside that pointed-to struct, not in ctx->di/si
// directly.  We must bpf_probe_read_kernel the inner pt_regs to
// get the target PID.

#include "common.bpf.h"

#define EPERM 1

// update_heartbeat writes the current timestamp to the heartbeat map
// so the Go-side integrity sentinel can detect when BPF probes are
// detached or disabled. v0.9 self-healing integrity sentinel.
static __always_inline void update_heartbeat(void)
{
	__u32 key = 0;
	__u64 now = bpf_ktime_get_ns();
	bpf_map_update_elem(&agent_heartbeat, &key, &now, BPF_ANY);
}

// v0.9: signal white-list removed. ALL external signals to the agent
// are blocked — including SIGSTOP(19), SIGCONT(18), SIGTSTP(20).
// Primary enforcement is in LSM (lsm_selfprotect.bpf.c); this kprobe
// layer provides telemetry + retroactive response.
//
// should_kill_caller now covers ALL signals uniformly: SIGTERM from
// systemd (PID 1) is excluded, everything else triggers SIGKILL to
// the attacker. This is consistent with v0.9's audit-first philosophy
// — the LSM already denied the operation; counter-kill here is the
// retroactive enforcement layer.
static __always_inline int should_kill_caller(__u32 sig, __u32 current_pid)
{
	if (current_pid == 1) {
		// systemd is the only legitimate signal source (shutdown).
		// SIGTERM is allowed through; anything else from systemd
		// is blocked but NOT counter-killed (don't kill init).
		if (sig == 15) return 0;
		return 0; // block without killing systemd
	}
	return 1; // all signals from non-systemd → always kill
}

char _license[] SEC("license") = "GPL";

// __x64_sys_kill(struct pt_regs *regs)
// regs->di = pid (target), regs->si = sig
SEC("kprobe/__x64_sys_kill")
int handle_kill(struct pt_regs *ctx)
{
	struct pt_regs *kregs = (struct pt_regs *)ctx->di;
	__u32 target_pid;
	__u32 sig;
	bpf_probe_read_kernel(&target_pid, sizeof(target_pid), &kregs->di);
	bpf_probe_read_kernel(&sig, sizeof(sig), &kregs->si);

	// v0.9: all signals blocked — no more white-list skip.
	__u32 key = 0;
	__u32 *agent = bpf_map_lookup_elem(&agent_pid, &key);
	if (!agent || target_pid != *agent)
		return 0;

	// Skip self-signals (Go runtime tgkill feedback loop).
	__u64 id = bpf_get_current_pid_tgid();
	__u32 current_pid = id >> 32;
	if (current_pid == *agent)
		return 0;

	update_heartbeat();

	// Enforce synchronously: make the kill syscall fail.
	bpf_override_return(ctx, -EPERM);

	if (should_kill_caller(sig, current_pid)) {
		bpf_send_signal(9); // SIGKILL to current (attacker)
	}

	struct edr_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EDR_EVENT_SELFPROTECT;
	e->timestamp_ns = bpf_ktime_get_ns();

	e->pid  = current_pid;  // attacker PID
	e->ppid = target_pid;   // agent PID
	e->tgid = (__u32)id;
	e->uid  = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__builtin_memcpy(e->filename, "sys_kill", 9);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// __x64_sys_tgkill(struct pt_regs *regs)
// regs->di = tgid, regs->si = tid, regs->dx = sig
SEC("kprobe/__x64_sys_tgkill")
int handle_tgkill(struct pt_regs *ctx)
{
	struct pt_regs *kregs = (struct pt_regs *)ctx->di;
	__u32 target_tgid, target_tid, sig;
	bpf_probe_read_kernel(&target_tgid, sizeof(target_tgid), &kregs->di);
	bpf_probe_read_kernel(&target_tid,  sizeof(target_tid),  &kregs->si);
	bpf_probe_read_kernel(&sig, sizeof(sig), &kregs->dx);

	// v0.9: all signals blocked.
	__u32 key = 0;
	__u32 *agent = bpf_map_lookup_elem(&agent_pid, &key);
	if (!agent || (target_tgid != *agent && target_tid != *agent))
		return 0;

	// Skip self-signals (Go runtime tgkill feedback loop).
	__u64 id = bpf_get_current_pid_tgid();
	__u32 current_pid = id >> 32;
	if (current_pid == *agent)
		return 0;

	update_heartbeat();

	// Enforce synchronously.
	bpf_override_return(ctx, -EPERM);
	if (should_kill_caller(sig, current_pid)) {
		bpf_send_signal(9);
	}

	struct edr_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EDR_EVENT_SELFPROTECT;
	e->timestamp_ns = bpf_ktime_get_ns();

	e->pid  = current_pid;
	e->ppid = (target_tid != 0) ? target_tid : target_tgid;
	e->tgid = (__u32)id;
	e->uid  = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__builtin_memcpy(e->filename, "sys_tgkill", 11);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// __x64_sys_ptrace(struct pt_regs *regs)
// regs->di = request, regs->si = pid
SEC("kprobe/__x64_sys_ptrace")
int handle_ptrace(struct pt_regs *ctx)
{
	struct pt_regs *kregs = (struct pt_regs *)ctx->di;
	__u32 target_pid;
	bpf_probe_read_kernel(&target_pid, sizeof(target_pid), &kregs->si);

	__u32 key = 0;
	__u32 *agent = bpf_map_lookup_elem(&agent_pid, &key);
	if (!agent || target_pid != *agent)
		return 0;

	// Skip self-ptrace (Go runtime).
	__u64 id = bpf_get_current_pid_tgid();
	__u32 current_pid = id >> 32;
	if (current_pid == *agent)
		return 0;

	update_heartbeat();

	// Enforce synchronously, then terminate the ptrace attacker.
	bpf_override_return(ctx, -EPERM);
	bpf_send_signal(9); // SIGKILL

	struct edr_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EDR_EVENT_SELFPROTECT;
	e->timestamp_ns = bpf_ktime_get_ns();

	e->pid  = current_pid;
	e->ppid = target_pid;
	e->tgid = (__u32)id;
	e->uid  = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__builtin_memcpy(e->filename, "sys_ptrace", 11);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// __x64_sys_pidfd_send_signal(struct pt_regs *regs)
// regs->di = pidfd, regs->si = sig, regs->dx = info, regs->cx = flags
SEC("kprobe/__x64_sys_pidfd_send_signal")
int handle_pidfd_send_signal(struct pt_regs *ctx)
{
	struct pt_regs *kregs = (struct pt_regs *)ctx->di;
	__u32 sig;
	bpf_probe_read_kernel(&sig, sizeof(sig), &kregs->si);

	// v0.9: all signals blocked.
	__u32 key = 0;
	__u32 *agent = bpf_map_lookup_elem(&agent_pid, &key);
	if (!agent)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	__u32 current_pid = id >> 32;
	if (current_pid == *agent)
		return 0;

	update_heartbeat();

	bpf_override_return(ctx, -EPERM);
	if (should_kill_caller(sig, current_pid)) {
		bpf_send_signal(9);
	}
	return 0;
}

// __x64_sys_process_vm_writev(struct pt_regs *regs)
// regs->di = pid (target process to write into)
// Blocks direct memory write attacks on the agent process.
// process_vm_writev() allows writing to another process's memory
// without ptrace, bypassing traditional anti-debugging protections.
SEC("kprobe/__x64_sys_process_vm_writev")
int handle_process_vm_writev(struct pt_regs *ctx)
{
	struct pt_regs *kregs = (struct pt_regs *)ctx->di;
	__u32 target_pid;
	bpf_probe_read_kernel(&target_pid, sizeof(target_pid), &kregs->di);

	__u32 key = 0;
	__u32 *agent = bpf_map_lookup_elem(&agent_pid, &key);
	if (!agent || target_pid != *agent)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	__u32 current_pid = id >> 32;
	if (current_pid == *agent)
		return 0;

	update_heartbeat();

	// process_vm_writev targeting the agent process is always hostile.
	// Block the syscall and terminate the attacker.
	bpf_override_return(ctx, -EPERM);
	bpf_send_signal(9);

	// Emit self-protection audit event.
	struct edr_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EDR_EVENT_SELFPROTECT;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid  = current_pid;
	e->ppid = target_pid;
	e->tgid = (__u32)id;
	e->uid  = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__builtin_memcpy(e->filename, "process_vm_writev", 18);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// __x64_sys_process_vm_readv(struct pt_regs *regs)
// regs->di = pid (target process to read from)
// Blocks direct memory read attacks on the agent process — v0.9.
// process_vm_readv() allows reading another process's memory
// without ptrace, enabling information disclosure and credential
// theft from the EDR agent.
SEC("kprobe/__x64_sys_process_vm_readv")
int handle_process_vm_readv(struct pt_regs *ctx)
{
	struct pt_regs *kregs = (struct pt_regs *)ctx->di;
	__u32 target_pid;
	bpf_probe_read_kernel(&target_pid, sizeof(target_pid), &kregs->di);

	__u32 key = 0;
	__u32 *agent = bpf_map_lookup_elem(&agent_pid, &key);
	if (!agent || target_pid != *agent)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	__u32 current_pid = id >> 32;
	if (current_pid == *agent)
		return 0;

	update_heartbeat();

	bpf_override_return(ctx, -EPERM);
	bpf_send_signal(9);

	struct edr_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EDR_EVENT_SELFPROTECT;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid  = current_pid;
	e->ppid = target_pid;
	e->tgid = (__u32)id;
	e->uid  = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__builtin_memcpy(e->filename, "process_vm_readv", 17);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// v0.9.1: __x64_sys_prctl audit — detects prctl-based evasion.
// Prctl can manipulate process identity (PR_SET_MM, PR_SET_NAME),
// install seccomp filters, or set subreaper flags.
// Detection only — no override, no kill. Enforcement via LSM
// fmod_ret on security_task_prctl is a future step.
#define PR_SET_PDEATHSIG    1
#define PR_SET_MM           6
#define PR_SET_NAME         15
#define PR_SET_SECCOMP      22
#define PR_SET_NO_NEW_PRIVS 36
#define PR_SET_CHILD_SUBREAPER 39

SEC("kprobe/__x64_sys_prctl")
int handle_prctl(struct pt_regs *ctx)
{
	struct pt_regs *kregs = (struct pt_regs *)ctx->di;
	__u32 option;
	bpf_probe_read_kernel(&option, sizeof(option), &kregs->di);

	switch (option) {
	case PR_SET_MM:
	case PR_SET_NAME:
	case PR_SET_SECCOMP:
	case PR_SET_NO_NEW_PRIVS:
	case PR_SET_CHILD_SUBREAPER:
		break;
	default:
		return 0;
	}

	__u32 key = 0;
	__u32 *agent = bpf_map_lookup_elem(&agent_pid, &key);
	__u64 id = bpf_get_current_pid_tgid();
	__u32 current_pid = id >> 32;

	if (agent && current_pid == *agent)
		return 0;

	struct edr_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EDR_EVENT_SELFPROTECT;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid  = current_pid;
	e->tgid = (__u32)id;
	e->uid  = (__u32)bpf_get_current_uid_gid();
	e->_reserved = option;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__builtin_memcpy(e->filename, "sys_prctl", 10);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
