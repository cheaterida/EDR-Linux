// internal/bpf/probes/common.bpf.h
// Shared types and ring buffer map for the v0.2 BPF probes.
//
// The C-side event struct is the binary contract with the Go
// loader (Step 4). It must stay in sync with internal/bpf/event.go
// consumers; layout changes here require a SchemaVersion bump in
// the Go side (R-L3).

#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define EDR_EVENT_EXEC         1
#define EDR_EVENT_FORK         2
#define EDR_EVENT_EXIT         3
#define EDR_EVENT_CONNECT      4
#define EDR_EVENT_SELFPROTECT  5
#define EDR_EVENT_PTRACE_ENH   6
#define EDR_EVENT_LDPRELOAD    7
#define EDR_EVENT_INSTRUMENT   8
#define EDR_EVENT_SENSOR_TAMPER 9
#define EDR_EVENT_PRIVESC      10
#define EDR_EVENT_MODULE_LOAD  11
#define EDR_EVENT_MODULE_UNLOAD 12
#define EDR_EVENT_BPF_OP       13

// edr_event is the payload written to the ring buffer by every
// probe. The fields are densely packed; padding is explicit so
// the C and Go layouts can be diffed with a hex editor if they
// ever drift.
struct edr_event {
	__u8	type; // EDR_EVENT_*
	__u8	_pad0[3];
	__u32	_reserved; // ptrace_enh: ptrace request type
	__u64	timestamp_ns;
	__u32	pid;
	__u32	ppid;
	__u32	tgid;
	__u32	uid;
	char	comm[16];
	char	filename[256]; // exec: argv[0] / resolved path
	__u8	family; // connect: AF_INET / AF_INET6
	__u8	_pad1[3];
	__u16	dport; // connect: remote port, host byte order
	__u32	daddr_v4; // connect: v4 remote addr, network byte order
	__u8	daddr_v6[16]; // connect: v6 remote addr, network byte order
};

// events is the ring buffer shared by every probe in the same
// .bpf.c. 256 KiB is large enough for a burst of exec storms
// without forcing the consumer into head-of-line blocking.
//
// __attribute__((weak)) lets bpftool gen object dedup the
// symbol when linking multiple .bpf.o into a single combined
// .o. Without it, the linker errors with "conflicting
// non-weak symbol #15 (events)".
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps") __attribute__((weak));

// agent_pid stores the EDR agent PID so kprobes on sys_kill /
// sys_tgkill / sys_ptrace can compare the target argument against
// it. Single-entry ARRAY: key=0 → value=agent PID (u32). The Go
// loader writes it once at startup.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} agent_pid SEC(".maps") __attribute__((weak));

// blacklist_comm is a hash map of process comm (up to 16 bytes) to
// a non-zero sentinel byte. The exec probe checks this map after
// submitting the ring buffer event; if present, bpf_send_signal(9)
// instantly SIGKILLs the new process before userspace code runs.
// The Go loader populates it from process_access.blacklist at
// startup and on policy reload.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, char[16]);
	__type(value, __u8);
} blacklist_comm SEC(".maps") __attribute__((weak));

// blacklist_filename is a hash map of full exec path (up to 256 bytes)
// to a non-zero sentinel byte. This covers process names longer than
// 15 characters (TASK_COMM_LEN) that get truncated in blacklist_comm.
// The exec probe checks this map on a blacklist_comm miss.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, char[256]);
	__type(value, __u8);
} blacklist_filename SEC(".maps") __attribute__((weak));

// ldpreload_kill is a single-entry ARRAY toggle. When set to non-zero,
// the ldpreload probe immediately SIGKILLs the current task after it
// emits the event, avoiding userspace response races for short-lived
// exec transitions.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} ldpreload_kill SEC(".maps") __attribute__((weak));

// net_blacklist_enabled is a single-entry ARRAY toggle for ring0
// network blocking. When set to non-zero, the connect probe will
// SIGKILL the connecting process if the destination matches
// net_blacklist_ip or net_blacklist_port maps.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} net_blacklist_enabled SEC(".maps") __attribute__((weak));

// net_blacklist_ip is a hash map of IPv4 destination addresses
// (network byte order, __u32) to non-zero sentinel. When the
// connect probe observes a matching outbound connection and
// net_blacklist_enabled is set, it issues bpf_send_signal(SIGKILL).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, __u32);
	__type(value, __u8);
} net_blacklist_ip SEC(".maps") __attribute__((weak));

// net_blacklist_port is a hash map of destination ports (host byte
// order, __u16 stored as __u32 for alignment) to non-zero sentinel.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u8);
} net_blacklist_port SEC(".maps") __attribute__((weak));
