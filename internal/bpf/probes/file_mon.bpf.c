// internal/bpf/probes/file_mon.bpf.c
// v0.9.1: File operation monitoring via tracepoints.
//
// Monitors file deletion and rename with full path capture:
//   tp/syscalls/sys_enter_unlinkat — directory-relative deletion
//   tp/syscalls/sys_enter_unlink   — absolute path deletion
//   tp/syscalls/sys_enter_renameat — directory-relative rename
//
// Each emits EDR_EVENT_FILE_OP to the shared ring buffer.
// The Go-side policy engine matches these against file rules
// (SELF*, PERSIST*, B* rules in policy.target.json).

#include "common.bpf.h"

char _license[] SEC("license") = "GPL";

// File operation subtypes
#define FILE_OP_UNLINKAT  1
#define FILE_OP_UNLINK    2
#define FILE_OP_RENAMEAT  3

static __always_inline void emit_file_op(__u8 subtype, const char *filename)
{
	struct edr_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;

	__u64 id = bpf_get_current_pid_tgid();
	__builtin_memset(e, 0, sizeof(*e));
	e->type = EDR_EVENT_FILE_OP;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid  = (__u32)(id >> 32);
	e->tgid = (__u32)id;
	e->uid  = (__u32)bpf_get_current_uid_gid();
	e->ppid = 0;
	e->_reserved = subtype;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// Copy filename (max 255 chars + null)
	if (filename) {
		__builtin_memset(e->filename, 0, sizeof(e->filename));
		bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);
	}

	bpf_ringbuf_submit(e, 0);
}

// sys_enter_unlinkat(int dfd, const char *pathname, int flag)
SEC("tp/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	const char *pathname = (const char *)ctx->args[1];
	emit_file_op(FILE_OP_UNLINKAT, pathname);
	return 0;
}

// sys_enter_unlink(const char *pathname)
SEC("tp/syscalls/sys_enter_unlink")
int handle_unlink(struct trace_event_raw_sys_enter *ctx)
{
	const char *pathname = (const char *)ctx->args[0];
	emit_file_op(FILE_OP_UNLINK, pathname);
	return 0;
}

// sys_enter_renameat(int olddfd, const char *oldname,
//                     int newdfd, const char *newname, unsigned int flags)
SEC("tp/syscalls/sys_enter_renameat")
int handle_renameat(struct trace_event_raw_sys_enter *ctx)
{
	const char *oldname = (const char *)ctx->args[1];
	emit_file_op(FILE_OP_RENAMEAT, oldname);
	return 0;
}
