// internal/bpf/probes/connect.bpf.c
// Tracepoint: inet_sock_set_state
// Fires on TCP/UDP socket state transitions. The tracepoint
// payload includes sport, dport, family, and the v4/v6 source and
// dest addresses directly — no sock-pointer chase required.
//
// We filter on newstate == TCP_ESTABLISHED (= 1) to capture
// outbound connect() calls. Listening sockets and accept() paths
// fire with different state transitions and are out of scope for
// v0.2.
//
// Output: ring buffer event of struct edr_event with type=4.

#include "common.bpf.h"

char _license[] SEC("license") = "GPL";

// TCP_ESTABLISHED is the only state we care about for connect
// observability. We hardcode the numeric value to keep the .bpf.c
// independent of the host headers.
#define TCP_ESTABLISHED 1

SEC("tp/sock/inet_sock_set_state")
int handle_connect(struct trace_event_raw_inet_sock_set_state *ctx)
{
	if (ctx->newstate != TCP_ESTABLISHED) {
		return 0;
	}

	struct edr_event *e;
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EDR_EVENT_CONNECT;
	e->timestamp_ns = bpf_ktime_get_ns();

	__u64 id = bpf_get_current_pid_tgid();
	e->pid = id >> 32;
	e->tgid = (__u32)id;
	e->uid = (__u32)bpf_get_current_uid_gid();

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->family = ctx->family;
	e->dport = ctx->dport;

	// The tracepoint fills the v4 OR v6 slot depending on
	// family. v4 uses network byte order in daddr[4]; v6 uses
	// raw bytes in daddr_v6[16]. The Go loader turns these
	// into human-readable strings.
	if (ctx->family == 2 /* AF_INET */) {
		bpf_probe_read_kernel(&e->daddr_v4, sizeof(e->daddr_v4),
				      &ctx->daddr);
	} else if (ctx->family == 10 /* AF_INET6 */) {
		bpf_probe_read_kernel(e->daddr_v6, sizeof(e->daddr_v6),
				      &ctx->daddr_v6);
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}
