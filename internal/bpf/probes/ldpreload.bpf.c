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

	// Try to read first env string to detect LD_PRELOAD
	char buf[64];
	__builtin_memset(buf, 0, sizeof(buf));
	// Read first envp entry pointer
	char *first_env = NULL;
	bpf_probe_read_user(&first_env, sizeof(first_env), (void *)envp_addr);
	if (first_env) {
		bpf_probe_read_user(buf, sizeof(buf), first_env);
		// Check for LD_PRELOAD=
		for (int j = 0; j < 53; j++) {
			if (buf[j]   == 'L' && buf[j+1] == 'D' && buf[j+2] == '_' &&
			    buf[j+3] == 'P' && buf[j+4] == 'R' && buf[j+5] == 'E' &&
			    buf[j+6] == 'L' && buf[j+7] == 'O' && buf[j+8] == 'A' &&
			    buf[j+9] == 'D' && buf[j+10] == '=') {
				// Copy LD_PRELOAD value
				for (int k = 0; k < 245 && j + 11 + k < 64; k++) {
					e->filename[k] = buf[j + 11 + k];
					if (buf[j + 11 + k] == '\0')
						break;
				}
				bpf_ringbuf_submit(e, 0);
				return 0;
			}
		}
	}

	// No LD_PRELOAD found — drop the event
	bpf_ringbuf_discard(e, 0);
	return 0;
}
