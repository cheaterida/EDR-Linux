// internal/bpf/probes/fork.bpf.c
// Tracepoint: sched_process_fork
// Fires when a process forks. Captures parent_pid and child_pid
// so the Go side can reconstruct process lineage without procfs.
//
// Output: ring buffer event of struct edr_event with type=2.

#include "common.bpf.h"

char _license[] SEC("license") = "GPL";

SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	struct edr_event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EDR_EVENT_FORK;
	e->timestamp_ns = bpf_ktime_get_ns();

	e->pid  = (__u32)ctx->child_pid;
	e->ppid = (__u32)ctx->parent_pid;
	// tgid is inherited by the child; the calling thread's tgid
	// represents the parent process.
	__u64 id = bpf_get_current_pid_tgid();
	e->tgid = (__u32)id;
	e->uid  = (__u32)bpf_get_current_uid_gid();

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
