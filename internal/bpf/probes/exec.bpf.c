// internal/bpf/probes/exec.bpf.c
// Tracepoint: sched_process_exec
// Fires when a process successfully calls execve. The tracepoint
// carries a userspace pointer to the new comm and the filename
// that was exec'd; we copy them into a ring buffer event.
//
// Output: ring buffer event of struct edr_event with type=1.

#include "common.bpf.h"

char _license[] SEC("license") = "GPL";

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct edr_event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EDR_EVENT_EXEC;
	e->timestamp_ns = bpf_ktime_get_ns();

	__u64 id = bpf_get_current_pid_tgid();
	e->pid = id >> 32;
	e->tgid = (__u32)id;
	e->uid = (__u32)bpf_get_current_uid_gid();

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	// __data_loc_filename is a 16-bit offset (lower bits) into the
	// variable-length data section that follows the fixed struct.
	// The kernel has already copied the userspace string into a
	// kernel buffer, so bpf_probe_read_kernel_str is the right
	// primitive. bpf_probe_read_user_str would fault on a kernel
	// address.
	__u16 off = (__u16)(ctx->__data_loc_filename & 0xFFFF);
	(void)bpf_probe_read_kernel_str(e->filename, sizeof(e->filename),
				       (const char *)ctx + off);

	// Ring0 blacklist check: if the new process's comm matches an
	// entry in blacklist_comm, send SIGKILL immediately before the
	// process runs any userspace code. Must happen *before*
	// bpf_ringbuf_submit because the verifier tracks ringbuf memory
	// ownership; after submit the pointer is "released" and can't be
	// used as a map key. bpf_send_signal available since kernel 5.4.
	__u8 *action = bpf_map_lookup_elem(&blacklist_comm, e->comm);
	if (action && *action != 0) {
		bpf_ringbuf_submit(e, 0);
		bpf_send_signal(9); // SIGKILL
		return 0;
	}

	// Second check: blacklist_filename covers process names longer
	// than 15 chars (TASK_COMM_LEN) that get truncated in comm.
	// Uses the full exec path resolved by the kernel.
	__u8 *fn_action = bpf_map_lookup_elem(&blacklist_filename, e->filename);
	if (fn_action && *fn_action != 0) {
		bpf_ringbuf_submit(e, 0);
		bpf_send_signal(9); // SIGKILL
		return 0;
	}

	bpf_ringbuf_submit(e, 0);

	return 0;
}
