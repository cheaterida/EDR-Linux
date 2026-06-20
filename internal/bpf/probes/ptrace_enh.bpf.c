// internal/bpf/probes/ptrace_enh.bpf.c
// Enhanced ptrace detection: fires on ALL ptrace calls, not just
// agent-targeting ones. Detects anti-debug self-checks
// (PTRACE_TRACEME) and ptrace attach attempts.
//
// Output: ring buffer event with type=EDR_EVENT_PTRACE_ENH.
// _reserved field carries the ptrace request type.
// filename carries a human-readable request label.

#include "common.bpf.h"

char _license[] SEC("license") = "GPL";

// ptrace request constants (from linux/ptrace.h)
#define PTRACE_TRACEME      0
#define PTRACE_PEEKTEXT     1
#define PTRACE_PEEKDATA     2
#define PTRACE_PEEKUSER     3
#define PTRACE_POKETEXT     4
#define PTRACE_POKEDATA     5
#define PTRACE_POKEUSER     6
#define PTRACE_CONT         7
#define PTRACE_KILL         8
#define PTRACE_SINGLESTEP   9
#define PTRACE_ATTACH       16
#define PTRACE_DETACH       17
#define PTRACE_SYSCALL       24

// __x64_sys_ptrace(struct pt_regs *regs)
// regs->di = request, regs->si = pid, regs->dx = addr, regs->r10 = data
SEC("kprobe/__x64_sys_ptrace")
int handle_ptrace_enh(struct pt_regs *ctx)
{
	struct pt_regs *kregs = (struct pt_regs *)ctx->di;
	__u64 request;
	__u32 target_pid;

	if (!kregs)
		return 0;

	// On syscall-wrapper kernels __x64_sys_ptrace receives a single
	// pt_regs * argument whose di/si hold the real syscall args.
	bpf_probe_read_kernel(&request, sizeof(request), &kregs->di);
	bpf_probe_read_kernel(&target_pid, sizeof(target_pid), &kregs->si);

	// Get caller identity
	__u64 id = bpf_get_current_pid_tgid();
	__u32 caller_pid = id >> 32;

	// Skip if caller is targeting itself with TRACEME (common pattern,
	// but we still want to detect it as anti-debug)
	// For non-TRACEME: skip if target is not interesting
	// We emit events for: TRACEME (anti-debug), ATTACH, and
	// any ptrace on a different process
	if (request != PTRACE_TRACEME && target_pid == caller_pid)
		return 0;

	struct edr_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EDR_EVENT_PTRACE_ENH;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = caller_pid;
	e->ppid = target_pid;
	e->tgid = (__u32)id;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->_reserved = (__u32)request;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// Label the request type in filename for easy Go-side parsing
	switch (request) {
	case PTRACE_TRACEME:
		__builtin_memcpy(e->filename, "PTRACE_TRACEME", 15);
		break;
	case PTRACE_ATTACH:
		__builtin_memcpy(e->filename, "PTRACE_ATTACH", 14);
		break;
	case PTRACE_DETACH:
		__builtin_memcpy(e->filename, "PTRACE_DETACH", 14);
		break;
	case PTRACE_CONT:
		__builtin_memcpy(e->filename, "PTRACE_CONT", 12);
		break;
	case PTRACE_KILL:
		__builtin_memcpy(e->filename, "PTRACE_KILL", 12);
		break;
	case PTRACE_SINGLESTEP:
		__builtin_memcpy(e->filename, "PTRACE_SINGLESTEP", 18);
		break;
	case PTRACE_SYSCALL:
		__builtin_memcpy(e->filename, "PTRACE_SYSCALL", 15);
		break;
	case PTRACE_PEEKTEXT:
		__builtin_memcpy(e->filename, "PTRACE_PEEKTEXT", 16);
		break;
	case PTRACE_PEEKDATA:
		__builtin_memcpy(e->filename, "PTRACE_PEEKDATA", 16);
		break;
	case PTRACE_POKETEXT:
		__builtin_memcpy(e->filename, "PTRACE_POKETEXT", 16);
		break;
	case PTRACE_POKEDATA:
		__builtin_memcpy(e->filename, "PTRACE_POKEDATA", 16);
		break;
	default:
		__builtin_memcpy(e->filename, "PTRACE_OTHER", 13);
		break;
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}
