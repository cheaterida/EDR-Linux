// internal/bpf/probes/bpf_guard.bpf.c
// v0.16: Kprobe on __x64_sys_bpf to block unauthorized BPF map writes.
//
// handle_bpf_write — kprobe/__x64_sys_bpf
//
// Attackers who obtain root can call bpf(BPF_MAP_UPDATE_ELEM, ...)
// directly (no bpftool needed) to zero EDR's agent_pid map and then
// kill the agent. This probe blocks the write at ring0 before the
// kernel processes it.
//
// Controlled by bpf_guard_enabled map — Phase 1/2: disabled (monitor only),
// Phase 3/4: enabled (hard block).
//
// WITH CONFIG_ARCH_HAS_SYSCALL_WRAPPER: __x64_sys_bpf receives a single
// pointer to pt_regs. Real arguments are inside kregs->di (cmd),
// kregs->si (uattr).

#include "common.bpf.h"

char _license[] SEC("license") = "GPL";

#define BPF_MAP_UPDATE_ELEM 2
#define BPF_PROG_DETACH    8
#define EPERM 1

// bpf_guard_enabled — single-entry ARRAY toggle. When set to non-zero,
// the kprobe blocks BPF_MAP_UPDATE_ELEM and BPF_PROG_DETACH from
// non-edr-agent processes. The Go loader sets this at startup.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} bpf_guard_enabled SEC(".maps") __attribute__((weak));

SEC("kprobe/__x64_sys_bpf")
int handle_bpf_write(struct pt_regs *ctx)
{
    // Check toggle — bail out early if guard is disabled.
    __u32 key = 0;
    __u8 *enabled = bpf_map_lookup_elem(&bpf_guard_enabled, &key);
    if (!enabled || *enabled == 0)
        return 0;

    // Read cmd (first arg) from kernel registers.
    struct pt_regs *kregs = (struct pt_regs *)ctx->di;
    __u32 cmd;
    bpf_probe_read_kernel(&cmd, sizeof(cmd), &kregs->di);

    // Only block map writes and program detach — other bpf commands
    // are not our concern.
    if (cmd != BPF_MAP_UPDATE_ELEM && cmd != BPF_PROG_DETACH)
        return 0;

    // Skip self-operations (EDR agent updating its own maps).
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (__builtin_memcmp(comm, "edr-agent", 9) == 0)
        return 0;

    // Block the bpf() syscall — return -EPERM to caller.
    // bpf_send_signal(9) kills the attacker process for immediate
    // response (same pattern as selfprotect.bpf.c).
    bpf_override_return(ctx, -EPERM);
    bpf_send_signal(9);

    // Emit a self-protection event for auditing.
    struct edr_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    __builtin_memset(e, 0, sizeof(*e));
    e->type = EDR_EVENT_SELFPROTECT;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->_reserved = cmd;          // BPF_MAP_UPDATE_ELEM or BPF_PROG_DETACH
    e->pid = (__u32)(id >> 32);  // attacker PID
    e->tgid = (__u32)id;
    e->uid = (__u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->filename, "BPF_MAP_UPDATE_ELEM", 21);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// handle_init_module — kprobe/__x64_sys_init_module
// Blocks kernel module loading from non-edr-agent processes when
// bpf_guard is enabled. Attackers may attempt to load a rootkit LKM
// to disable EDR protections from kernel space.
SEC("kprobe/__x64_sys_init_module")
int handle_init_module(struct pt_regs *ctx)
{
    __u32 key = 0;
    __u8 *enabled = bpf_map_lookup_elem(&bpf_guard_enabled, &key);
    if (!enabled || *enabled == 0)
        return 0;

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (__builtin_memcmp(comm, "edr-agent", 9) == 0)
        return 0;

    bpf_override_return(ctx, -EPERM);
    bpf_send_signal(9);

    struct edr_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    __builtin_memset(e, 0, sizeof(*e));
    e->type = EDR_EVENT_SELFPROTECT;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->_reserved = 1; // init_module
    e->pid = (__u32)(id >> 32);
    e->tgid = (__u32)id;
    e->uid = (__u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->filename, "sys_init_module", 16);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// handle_delete_module — kprobe/__x64_sys_delete_module
// Blocks kernel module unloading from non-edr-agent processes.
// Attackers may try to unload EDR's BPF support infrastructure
// or other security-critical kernel modules.
SEC("kprobe/__x64_sys_delete_module")
int handle_delete_module(struct pt_regs *ctx)
{
    __u32 key = 0;
    __u8 *enabled = bpf_map_lookup_elem(&bpf_guard_enabled, &key);
    if (!enabled || *enabled == 0)
        return 0;

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (__builtin_memcmp(comm, "edr-agent", 9) == 0)
        return 0;

    bpf_override_return(ctx, -EPERM);
    bpf_send_signal(9);

    struct edr_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    __builtin_memset(e, 0, sizeof(*e));
    e->type = EDR_EVENT_SELFPROTECT;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->_reserved = 2; // delete_module
    e->pid = (__u32)(id >> 32);
    e->tgid = (__u32)id;
    e->uid = (__u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->filename, "sys_delete_module", 18);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
