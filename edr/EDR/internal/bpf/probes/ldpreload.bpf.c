// LD_PRELOAD detection via tracepoint sys_enter_execve.
// Reads envp pointer from syscall args and emits EDR_EVENT_LDPRELOAD.
#include "common.bpf.h"

char _license[] SEC("license") = "GPL";

SEC("tp/syscalls/sys_enter_execve")
int handle_ldpreload(struct trace_event_raw_sys_enter *ctx)
{
	// On x86_64, ctx->args[2] = envp (3rd arg to execve)
	__u64 envp_addr = ctx->args[2];
	if (!envp_addr)
		return 0;

	struct edr_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EDR_EVENT_LDPRELOAD;
	e->timestamp_ns = bpf_ktime_get_ns();

	__u64 id = bpf_get_current_pid_tgid();
	e->pid = id >> 32;
	e->tgid = (__u32)id;
	e->uid = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// Scan the first few envp entries; LD_PRELOAD is often not envp[0].
#pragma unroll
	for (int i = 0; i < 8; i++) {
		char *env = NULL;
		char buf[256];
		__builtin_memset(buf, 0, sizeof(buf));

		bpf_probe_read_user(&env, sizeof(env), (void *)(envp_addr + i * sizeof(env)));
		if (!env)
			break;
		bpf_probe_read_user(buf, sizeof(buf), env);

		if (buf[0]  == 'L' && buf[1]  == 'D' && buf[2]  == '_' &&
		    buf[3]  == 'P' && buf[4]  == 'R' && buf[5]  == 'E' &&
		    buf[6]  == 'L' && buf[7]  == 'O' && buf[8]  == 'A' &&
		    buf[9]  == 'D' && buf[10] == '=') {
			#pragma unroll
			for (int j = 0; j < 245; j++) {
				e->filename[j] = buf[11 + j];
				if (buf[11 + j] == '\0')
					break;
			}
			bpf_ringbuf_submit(e, 0);
			__u32 zero = 0;
			__u8 *kill = bpf_map_lookup_elem(&ldpreload_kill, &zero);
			if (kill && *kill)
				bpf_send_signal(9);
			return 0;
		}
	}

	// No LD_PRELOAD found — drop the event
	bpf_ringbuf_discard(e, 0);
	return 0;
}
