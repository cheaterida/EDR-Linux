// internal/bpf/probes/exit.bpf.c
// Tracepoint: sched_process_exit
// Fires when a process exits. Captures the exiting pid so the
// Go side can prune its process table without waiting for the
// next procfs scan.
//
// Output: ring buffer event of struct edr_event with type=3.

#include "common.bpf.h"

char _license[] SEC("license") = "GPL";

SEC("tp/sched/sched_process_exit")
int handle_exit(void *ctx)
{
	struct edr_event *e;

	(void)ctx;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EDR_EVENT_EXIT;
	e->timestamp_ns = bpf_ktime_get_ns();

	// On sched_process_exit the current task is the exiting task, so
	// current_pid_tgid is enough and avoids depending on a kernel-
	// specific raw tracepoint struct name in vmlinux.h.
	__u64 id = bpf_get_current_pid_tgid();
	e->pid  = (__u32)(id >> 32);
	e->tgid = (__u32)id;
	e->uid  = (__u32)bpf_get_current_uid_gid();

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
