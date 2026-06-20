//go:build bpf

// libbpf-backed Loader. Build with -tags bpf to enable; the
// default build keeps only the FakeLoader so `go test ./...`
// works on hosts without libbpf or CAP_BPF. R-CLI1: both
// build paths must be reproducible.
//
// The C bridge is inlined in the cgo preamble below so the
// cgo tool emits it exactly once (in the auto-generated
// loader_libbpf.cgo2.c). The original .c/.h split is kept
// in the git history if someone prefers a separate file.
package bpf

/*
#cgo CFLAGS: -I/usr/include
#cgo LDFLAGS: -lbpf -lelf -lz
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// Forward declaration for the Go-side callback that
// ring_buffer__new will invoke. The //export directive in Go
// declares it the other way (Go → C), but cgo processes the
// preamble before parsing //export, so this side needs an
// explicit prototype to keep -Wimplicit-function-declaration
// quiet. R-SCHEMA1: the signature here is the contract — the
// ring buffer callback in libbpf 1.0+ is (ctx, data, size).
extern int edr_deliver_event(void *ctx, void *data, size_t size);

struct edr_loader {
	struct bpf_object   *obj;
	struct bpf_link     *exec_link;
	struct bpf_link     *connect_link;
	struct bpf_link     *fork_link;              // best-effort
	struct bpf_link     *exit_link;              // best-effort
	struct bpf_link     *selfprotect_kill_link;  // best-effort
	struct bpf_link     *selfprotect_tgkill_link;// best-effort
	struct bpf_link     *selfprotect_ptrace_link;// best-effort
	struct bpf_link     *selfprotect_pidfd_send_signal_link;// best-effort
	struct bpf_link     *ptrace_enh_link;       // best-effort v0.4
	struct bpf_link     *ldpreload_link;        // best-effort v0.4
	struct bpf_link     *instrument_link;       // best-effort v0.4
	struct bpf_link     *lsm_task_kill_link;    // enforce self-protect
	struct bpf_link     *lsm_ptrace_link;       // enforce self-protect
	struct bpf_link     *privesc_setuid_link;   // best-effort v0.6
	struct bpf_link     *privesc_setgid_link;   // best-effort v0.6
	struct bpf_link     *privesc_capset_link;   // best-effort v0.6
	struct bpf_link     *module_init_link;      // v0.7 rootkit
	struct bpf_link     *module_finit_link;     // v0.7 rootkit
	struct bpf_link     *module_delete_link;    // v0.7 rootkit
	struct bpf_link     *bpf_op_link;           // v0.7 rootkit
	struct ring_buffer  *rb;
	int                  map_fd;
	int                  agent_pid_fd;            // agent_pid ARRAY map fd
	int                  blacklist_fd;            // blacklist_comm HASH map fd
	int                  blacklist_filename_fd;   // blacklist_filename HASH map fd
	int                  ldpreload_kill_fd;       // ldpreload_kill ARRAY map fd
	void                *go_ctx;
};

static int edr_on_event(void *ctx, void *data, size_t size)
{
	struct edr_loader *l = (struct edr_loader *)ctx;
	return edr_deliver_event(l->go_ctx, data, size);
}

static int edr_open(struct edr_loader **out, const char *obj_path)
{
	struct edr_loader *l;
	struct bpf_program *prog;
	struct bpf_map *map;

	if (!out || !obj_path)
		return -EINVAL;

	l = calloc(1, sizeof(*l));
	if (!l)
		return -ENOMEM;

	l->obj = bpf_object__open_file(obj_path, NULL);
	if (libbpf_get_error(l->obj)) {
		int err = (int)libbpf_get_error(l->obj);
		free(l);
		return err ? err : -EINVAL;
	}
	if (bpf_object__load(l->obj) < 0) {
		int err = -errno;
		bpf_object__close(l->obj);
		free(l);
		return err ? err : -EINVAL;
	}

	prog = bpf_object__find_program_by_name(l->obj, "handle_exec");
	if (!prog) {
		bpf_object__close(l->obj);
		free(l);
		return -ENOENT;
	}
	l->exec_link = bpf_program__attach_tracepoint(prog, "sched", "sched_process_exec");
	if (!l->exec_link || libbpf_get_error(l->exec_link)) {
		int err = l->exec_link ? (int)libbpf_get_error(l->exec_link) : -EINVAL;
		if (l->exec_link) bpf_link__destroy(l->exec_link);
		bpf_object__close(l->obj);
		free(l);
		return err;
	}

	prog = bpf_object__find_program_by_name(l->obj, "handle_connect");
	if (!prog) {
		bpf_link__destroy(l->exec_link);
		bpf_object__close(l->obj);
		free(l);
		return -ENOENT;
	}
	l->connect_link = bpf_program__attach_tracepoint(prog, "sock", "inet_sock_set_state");
	if (!l->connect_link || libbpf_get_error(l->connect_link)) {
		int err = l->connect_link ? (int)libbpf_get_error(l->connect_link) : -EINVAL;
		if (l->connect_link) bpf_link__destroy(l->connect_link);
		bpf_link__destroy(l->exec_link);
		bpf_object__close(l->obj);
		free(l);
		return err;
	}

	// Fork and exit are best-effort: missing programs or attach
	// failures are non-fatal. The combined .bpf.o may not include
	// them yet, and some kernels restrict which tracepoints are
	// attachable. The loader continues with just exec+connect if
	// either hook is unavailable.
	prog = bpf_object__find_program_by_name(l->obj, "handle_fork");
	if (prog) {
		l->fork_link = bpf_program__attach_tracepoint(prog, "sched", "sched_process_fork");
		if (!l->fork_link || libbpf_get_error(l->fork_link)) {
			if (l->fork_link) bpf_link__destroy(l->fork_link);
			l->fork_link = NULL;
		}
	}

	prog = bpf_object__find_program_by_name(l->obj, "handle_exit");
	if (prog) {
		l->exit_link = bpf_program__attach_tracepoint(prog, "sched", "sched_process_exit");
		if (!l->exit_link || libbpf_get_error(l->exit_link)) {
			if (l->exit_link) bpf_link__destroy(l->exit_link);
			l->exit_link = NULL;
		}
	}

	// Self-protection kprobes are best-effort. Missing symbols or
	// attach failures are non-fatal — the agent still functions
	// for telemetry. Errors are logged to stderr so operators can
	// diagnose silent kprobe failures.
	prog = bpf_object__find_program_by_name(l->obj, "handle_kill");
	if (prog) {
		l->selfprotect_kill_link = bpf_program__attach_kprobe(prog, false, "__x64_sys_kill");
		if (!l->selfprotect_kill_link) {
			fprintf(stderr, "bpf: attach_kprobe(__x64_sys_kill) returned NULL (symbol busy or blacklisted?)\n");
		} else if (libbpf_get_error(l->selfprotect_kill_link)) {
			fprintf(stderr, "bpf: attach_kprobe(__x64_sys_kill) error: %ld\n",
				libbpf_get_error(l->selfprotect_kill_link));
			bpf_link__destroy(l->selfprotect_kill_link);
			l->selfprotect_kill_link = NULL;
		}
	} else {
		fprintf(stderr, "bpf: program handle_kill not found in object file\n");
	}
	prog = bpf_object__find_program_by_name(l->obj, "handle_tgkill");
	if (prog) {
		l->selfprotect_tgkill_link = bpf_program__attach_kprobe(prog, false, "__x64_sys_tgkill");
		if (!l->selfprotect_tgkill_link) {
			fprintf(stderr, "bpf: attach_kprobe(__x64_sys_tgkill) returned NULL (symbol busy or blacklisted?)\n");
		} else if (libbpf_get_error(l->selfprotect_tgkill_link)) {
			fprintf(stderr, "bpf: attach_kprobe(__x64_sys_tgkill) error: %ld\n",
				libbpf_get_error(l->selfprotect_tgkill_link));
			bpf_link__destroy(l->selfprotect_tgkill_link);
			l->selfprotect_tgkill_link = NULL;
		}
	} else {
		fprintf(stderr, "bpf: program handle_tgkill not found in object file\n");
	}
	prog = bpf_object__find_program_by_name(l->obj, "handle_ptrace");
	if (prog) {
		l->selfprotect_ptrace_link = bpf_program__attach_kprobe(prog, false, "__x64_sys_ptrace");
		if (!l->selfprotect_ptrace_link) {
			fprintf(stderr, "bpf: attach_kprobe(__x64_sys_ptrace) returned NULL (symbol busy or blacklisted?)\n");
		} else if (libbpf_get_error(l->selfprotect_ptrace_link)) {
			fprintf(stderr, "bpf: attach_kprobe(__x64_sys_ptrace) error: %ld\n",
				libbpf_get_error(l->selfprotect_ptrace_link));
			bpf_link__destroy(l->selfprotect_ptrace_link);
			l->selfprotect_ptrace_link = NULL;
		}
	} else {
		fprintf(stderr, "bpf: program handle_ptrace not found in object file\n");
	}
	prog = bpf_object__find_program_by_name(l->obj, "handle_pidfd_send_signal");
	if (prog) {
		l->selfprotect_pidfd_send_signal_link = bpf_program__attach_kprobe(prog, false, "__x64_sys_pidfd_send_signal");
		if (!l->selfprotect_pidfd_send_signal_link) {
			fprintf(stderr, "bpf: attach_kprobe(__x64_sys_pidfd_send_signal) returned NULL\n");
		} else if (libbpf_get_error(l->selfprotect_pidfd_send_signal_link)) {
			fprintf(stderr, "bpf: attach_kprobe(__x64_sys_pidfd_send_signal) error: %ld\n",
				libbpf_get_error(l->selfprotect_pidfd_send_signal_link));
			bpf_link__destroy(l->selfprotect_pidfd_send_signal_link);
			l->selfprotect_pidfd_send_signal_link = NULL;
		}
	}

	// v0.4 anti-attack probes — best-effort, same pattern as selfprotect.
	prog = bpf_object__find_program_by_name(l->obj, "handle_ptrace_enh");
	if (prog) {
		l->ptrace_enh_link = bpf_program__attach_kprobe(prog, false, "__x64_sys_ptrace");
		if (!l->ptrace_enh_link) {
			fprintf(stderr, "bpf: attach_kprobe(__x64_sys_ptrace for ptrace_enh) returned NULL\n");
		} else if (libbpf_get_error(l->ptrace_enh_link)) {
			fprintf(stderr, "bpf: attach_kprobe(ptrace_enh) error: %ld\n",
				libbpf_get_error(l->ptrace_enh_link));
			bpf_link__destroy(l->ptrace_enh_link);
			l->ptrace_enh_link = NULL;
		}
	}
	prog = bpf_object__find_program_by_name(l->obj, "handle_ldpreload");
	if (prog) {
		l->ldpreload_link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_execve");
		if (!l->ldpreload_link) {
			fprintf(stderr, "bpf: attach_tracepoint(syscalls/sys_enter_execve for ldpreload) returned NULL\n");
		} else if (libbpf_get_error(l->ldpreload_link)) {
			fprintf(stderr, "bpf: attach_tracepoint(ldpreload) error: %ld\n",
				libbpf_get_error(l->ldpreload_link));
			bpf_link__destroy(l->ldpreload_link);
			l->ldpreload_link = NULL;
		}
	}
	prog = bpf_object__find_program_by_name(l->obj, "handle_instrument");
	if (prog) {
		l->instrument_link = bpf_program__attach_kprobe(prog, false, "__x64_sys_mmap");
		if (!l->instrument_link) {
			fprintf(stderr, "bpf: attach_kprobe(__x64_sys_mmap for instrument) returned NULL\n");
		} else if (libbpf_get_error(l->instrument_link)) {
			fprintf(stderr, "bpf: attach_kprobe(instrument) error: %ld\n",
				libbpf_get_error(l->instrument_link));
			bpf_link__destroy(l->instrument_link);
			l->instrument_link = NULL;
		}
	}

	// LSM self-protection is the actual blocking layer for fatal
	// signals and ptrace. These hooks are best-effort at attach time
	// so older kernels can still run telemetry, but operators should
	// treat a stderr error here as self-protection not enforced.
	prog = bpf_object__find_program_by_name(l->obj, "lsm_task_kill");
	if (prog) {
		l->lsm_task_kill_link = bpf_program__attach_lsm(prog);
		if (!l->lsm_task_kill_link) {
			fprintf(stderr, "bpf: attach_lsm(task_kill) returned NULL\n");
		} else if (libbpf_get_error(l->lsm_task_kill_link)) {
			fprintf(stderr, "bpf: attach_lsm(task_kill) error: %ld\n",
				libbpf_get_error(l->lsm_task_kill_link));
			bpf_link__destroy(l->lsm_task_kill_link);
			l->lsm_task_kill_link = NULL;
		}
	} else {
		fprintf(stderr, "bpf: program lsm_task_kill not found in object file\n");
	}
	prog = bpf_object__find_program_by_name(l->obj, "lsm_ptrace_access_check");
	if (prog) {
		l->lsm_ptrace_link = bpf_program__attach_lsm(prog);
		if (!l->lsm_ptrace_link) {
			fprintf(stderr, "bpf: attach_lsm(ptrace_access_check) returned NULL\n");
		} else if (libbpf_get_error(l->lsm_ptrace_link)) {
			fprintf(stderr, "bpf: attach_lsm(ptrace_access_check) error: %ld\n",
				libbpf_get_error(l->lsm_ptrace_link));
			bpf_link__destroy(l->lsm_ptrace_link);
			l->lsm_ptrace_link = NULL;
		}
	} else {
		fprintf(stderr, "bpf: program lsm_ptrace_access_check not found in object file\n");
	}

	// v0.6 privesc tracepoints — best-effort, same pattern as fork/exit.
	prog = bpf_object__find_program_by_name(l->obj, "handle_setuid");
	if (prog) {
		l->privesc_setuid_link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_setuid");
		if (!l->privesc_setuid_link) {
			fprintf(stderr, "bpf: attach_tracepoint(syscalls/sys_enter_setuid) returned NULL\n");
		} else if (libbpf_get_error(l->privesc_setuid_link)) {
			fprintf(stderr, "bpf: attach_tracepoint(setuid) error: %ld\n",
				libbpf_get_error(l->privesc_setuid_link));
			bpf_link__destroy(l->privesc_setuid_link);
			l->privesc_setuid_link = NULL;
		}
	}
	prog = bpf_object__find_program_by_name(l->obj, "handle_setgid");
	if (prog) {
		l->privesc_setgid_link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_setgid");
		if (!l->privesc_setgid_link) {
			fprintf(stderr, "bpf: attach_tracepoint(syscalls/sys_enter_setgid) returned NULL\n");
		} else if (libbpf_get_error(l->privesc_setgid_link)) {
			fprintf(stderr, "bpf: attach_tracepoint(setgid) error: %ld\n",
				libbpf_get_error(l->privesc_setgid_link));
			bpf_link__destroy(l->privesc_setgid_link);
			l->privesc_setgid_link = NULL;
		}
	}
	prog = bpf_object__find_program_by_name(l->obj, "handle_capset");
	if (prog) {
		l->privesc_capset_link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_capset");
		if (!l->privesc_capset_link) {
			fprintf(stderr, "bpf: attach_tracepoint(syscalls/sys_enter_capset) returned NULL\n");
		} else if (libbpf_get_error(l->privesc_capset_link)) {
			fprintf(stderr, "bpf: attach_tracepoint(capset) error: %ld\n",
				libbpf_get_error(l->privesc_capset_link));
			bpf_link__destroy(l->privesc_capset_link);
			l->privesc_capset_link = NULL;
		}
	}

	// v0.7 rootkit tracepoints — best-effort, same pattern as privesc.
	prog = bpf_object__find_program_by_name(l->obj, "handle_init_module");
	if (prog) {
		l->module_init_link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_init_module");
		if (!l->module_init_link) {
			fprintf(stderr, "bpf: attach_tracepoint(syscalls/sys_enter_init_module) returned NULL\n");
		} else if (libbpf_get_error(l->module_init_link)) {
			fprintf(stderr, "bpf: attach_tracepoint(init_module) error: %ld\n",
				libbpf_get_error(l->module_init_link));
			bpf_link__destroy(l->module_init_link);
			l->module_init_link = NULL;
		}
	}
	prog = bpf_object__find_program_by_name(l->obj, "handle_finit_module");
	if (prog) {
		l->module_finit_link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_finit_module");
		if (!l->module_finit_link) {
			fprintf(stderr, "bpf: attach_tracepoint(syscalls/sys_enter_finit_module) returned NULL\n");
		} else if (libbpf_get_error(l->module_finit_link)) {
			fprintf(stderr, "bpf: attach_tracepoint(finit_module) error: %ld\n",
				libbpf_get_error(l->module_finit_link));
			bpf_link__destroy(l->module_finit_link);
			l->module_finit_link = NULL;
		}
	}
	prog = bpf_object__find_program_by_name(l->obj, "handle_delete_module");
	if (prog) {
		l->module_delete_link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_delete_module");
		if (!l->module_delete_link) {
			fprintf(stderr, "bpf: attach_tracepoint(syscalls/sys_enter_delete_module) returned NULL\n");
		} else if (libbpf_get_error(l->module_delete_link)) {
			fprintf(stderr, "bpf: attach_tracepoint(delete_module) error: %ld\n",
				libbpf_get_error(l->module_delete_link));
			bpf_link__destroy(l->module_delete_link);
			l->module_delete_link = NULL;
		}
	}
	prog = bpf_object__find_program_by_name(l->obj, "handle_bpf");
	if (prog) {
		l->bpf_op_link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_bpf");
		if (!l->bpf_op_link) {
			fprintf(stderr, "bpf: attach_tracepoint(syscalls/sys_enter_bpf) returned NULL\n");
		} else if (libbpf_get_error(l->bpf_op_link)) {
			fprintf(stderr, "bpf: attach_tracepoint(bpf) error: %ld\n",
				libbpf_get_error(l->bpf_op_link));
			bpf_link__destroy(l->bpf_op_link);
			l->bpf_op_link = NULL;
		}
	}

	map = bpf_object__find_map_by_name(l->obj, "events");
	if (!map) {
		bpf_link__destroy(l->exec_link);
		bpf_link__destroy(l->connect_link);
		if (l->fork_link) bpf_link__destroy(l->fork_link);
		if (l->exit_link) bpf_link__destroy(l->exit_link);
	if (l->selfprotect_kill_link) bpf_link__destroy(l->selfprotect_kill_link);
	if (l->selfprotect_tgkill_link) bpf_link__destroy(l->selfprotect_tgkill_link);
	if (l->selfprotect_ptrace_link) bpf_link__destroy(l->selfprotect_ptrace_link);
	if (l->selfprotect_pidfd_send_signal_link) bpf_link__destroy(l->selfprotect_pidfd_send_signal_link);
		if (l->ptrace_enh_link) bpf_link__destroy(l->ptrace_enh_link);
		if (l->ldpreload_link) bpf_link__destroy(l->ldpreload_link);
		if (l->instrument_link) bpf_link__destroy(l->instrument_link);
		if (l->lsm_task_kill_link) bpf_link__destroy(l->lsm_task_kill_link);
		if (l->lsm_ptrace_link) bpf_link__destroy(l->lsm_ptrace_link);
		if (l->privesc_setuid_link) bpf_link__destroy(l->privesc_setuid_link);
		if (l->privesc_setgid_link) bpf_link__destroy(l->privesc_setgid_link);
		if (l->privesc_capset_link) bpf_link__destroy(l->privesc_capset_link);
		if (l->module_init_link) bpf_link__destroy(l->module_init_link);
		if (l->module_finit_link) bpf_link__destroy(l->module_finit_link);
		if (l->module_delete_link) bpf_link__destroy(l->module_delete_link);
		if (l->bpf_op_link) bpf_link__destroy(l->bpf_op_link);
		bpf_object__close(l->obj);
		free(l);
		return -ENOENT;
	}
	l->map_fd = bpf_map__fd(map);

	// Resolve optional map FDs for agent_pid and blacklist_comm so
	// the Go side can populate them at startup.
	{
		struct bpf_map *agent_map = bpf_object__find_map_by_name(l->obj, "agent_pid");
		l->agent_pid_fd = agent_map ? bpf_map__fd(agent_map) : -1;

		struct bpf_map *bl_map = bpf_object__find_map_by_name(l->obj, "blacklist_comm");
		l->blacklist_fd = bl_map ? bpf_map__fd(bl_map) : -1;

		struct bpf_map *blfn_map = bpf_object__find_map_by_name(l->obj, "blacklist_filename");
		l->blacklist_filename_fd = blfn_map ? bpf_map__fd(blfn_map) : -1;

		struct bpf_map *ldpreload_kill_map = bpf_object__find_map_by_name(l->obj, "ldpreload_kill");
		l->ldpreload_kill_fd = ldpreload_kill_map ? bpf_map__fd(ldpreload_kill_map) : -1;
	}

	l->rb = ring_buffer__new(l->map_fd, edr_on_event, l, NULL);
	if (!l->rb || libbpf_get_error(l->rb)) {
		int err = l->rb ? (int)libbpf_get_error(l->rb) : -EINVAL;
		if (l->rb) ring_buffer__free(l->rb);
		bpf_link__destroy(l->exec_link);
		bpf_link__destroy(l->connect_link);
		if (l->fork_link) bpf_link__destroy(l->fork_link);
		if (l->exit_link) bpf_link__destroy(l->exit_link);
	if (l->selfprotect_kill_link) bpf_link__destroy(l->selfprotect_kill_link);
	if (l->selfprotect_tgkill_link) bpf_link__destroy(l->selfprotect_tgkill_link);
	if (l->selfprotect_ptrace_link) bpf_link__destroy(l->selfprotect_ptrace_link);
	if (l->selfprotect_pidfd_send_signal_link) bpf_link__destroy(l->selfprotect_pidfd_send_signal_link);
		if (l->ptrace_enh_link) bpf_link__destroy(l->ptrace_enh_link);
		if (l->ldpreload_link) bpf_link__destroy(l->ldpreload_link);
		if (l->instrument_link) bpf_link__destroy(l->instrument_link);
		if (l->lsm_task_kill_link) bpf_link__destroy(l->lsm_task_kill_link);
		if (l->lsm_ptrace_link) bpf_link__destroy(l->lsm_ptrace_link);
		if (l->privesc_setuid_link) bpf_link__destroy(l->privesc_setuid_link);
		if (l->privesc_setgid_link) bpf_link__destroy(l->privesc_setgid_link);
		if (l->privesc_capset_link) bpf_link__destroy(l->privesc_capset_link);
		if (l->module_init_link) bpf_link__destroy(l->module_init_link);
		if (l->module_finit_link) bpf_link__destroy(l->module_finit_link);
		if (l->module_delete_link) bpf_link__destroy(l->module_delete_link);
		if (l->bpf_op_link) bpf_link__destroy(l->bpf_op_link);
		bpf_object__close(l->obj);
		free(l);
		return err;
	}

	*out = l;
	return 0;
}

static int edr_poll(struct edr_loader *l, int timeout_ms)
{
	if (!l)
		return -EINVAL;
	return ring_buffer__poll(l->rb, timeout_ms);
}

static void edr_close(struct edr_loader *l)
{
	if (!l)
		return;
	if (l->rb)
		ring_buffer__free(l->rb);
	if (l->exec_link)
		bpf_link__destroy(l->exec_link);
	if (l->connect_link)
		bpf_link__destroy(l->connect_link);
	if (l->fork_link)
		bpf_link__destroy(l->fork_link);
	if (l->exit_link)
		bpf_link__destroy(l->exit_link);
	if (l->selfprotect_kill_link)
		bpf_link__destroy(l->selfprotect_kill_link);
	if (l->selfprotect_tgkill_link)
		bpf_link__destroy(l->selfprotect_tgkill_link);
	if (l->selfprotect_ptrace_link)
		bpf_link__destroy(l->selfprotect_ptrace_link);
	if (l->selfprotect_pidfd_send_signal_link)
		bpf_link__destroy(l->selfprotect_pidfd_send_signal_link);
	if (l->ptrace_enh_link)
		bpf_link__destroy(l->ptrace_enh_link);
	if (l->ldpreload_link)
		bpf_link__destroy(l->ldpreload_link);
	if (l->instrument_link)
		bpf_link__destroy(l->instrument_link);
	if (l->lsm_task_kill_link)
		bpf_link__destroy(l->lsm_task_kill_link);
	if (l->lsm_ptrace_link)
		bpf_link__destroy(l->lsm_ptrace_link);
	if (l->privesc_setuid_link)
		bpf_link__destroy(l->privesc_setuid_link);
	if (l->privesc_setgid_link)
		bpf_link__destroy(l->privesc_setgid_link);
	if (l->privesc_capset_link)
		bpf_link__destroy(l->privesc_capset_link);
	if (l->module_init_link)
		bpf_link__destroy(l->module_init_link);
	if (l->module_finit_link)
		bpf_link__destroy(l->module_finit_link);
	if (l->module_delete_link)
		bpf_link__destroy(l->module_delete_link);
	if (l->bpf_op_link)
		bpf_link__destroy(l->bpf_op_link);
	if (l->obj)
		bpf_object__close(l->obj);
	free(l);
}

static void edr_set_go_ctx(struct edr_loader *h, void *ctx)
{
	if (!h)
		return;
	h->go_ctx = ctx;
}

// edr_set_agent_pid writes the agent PID into the agent_pid BPF ARRAY
// map so self-protection kprobes can detect kill/ptrace targeting us.
static int edr_set_agent_pid(struct edr_loader *l, __u32 pid)
{
	if (!l || l->agent_pid_fd < 0)
		return -EINVAL;
	__u32 key = 0;
	return bpf_map_update_elem(l->agent_pid_fd, &key, &pid, BPF_ANY) ? -errno : 0;
}

// edr_blacklist_add inserts a comm into the blacklist_comm BPF HASH map.
// The exec probe checks this map and calls bpf_send_signal(9) when a
// match is found.
static int edr_blacklist_add(struct edr_loader *l, const char *comm, __u8 action)
{
	if (!l || l->blacklist_fd < 0 || !comm)
		return -EINVAL;
	char key[16] = {0};
	int len = __builtin_strlen(comm);
	if (len > 15) len = 15;
	__builtin_memcpy(key, comm, len);
	return bpf_map_update_elem(l->blacklist_fd, key, &action, BPF_ANY) ? -errno : 0;
}

// edr_blacklist_clear removes all entries from the blacklist_comm BPF
// HASH map by repeatedly retrieving the first key (via bpf_map_get_next_key
// with NULL) and deleting it until the map is empty. Safe for empty maps.
static int edr_blacklist_clear(struct edr_loader *l)
{
	if (!l || l->blacklist_fd < 0)
		return -EINVAL;
	char key[16];
	while (bpf_map_get_next_key(l->blacklist_fd, NULL, key) == 0) {
		if (bpf_map_delete_elem(l->blacklist_fd, key))
			return -errno;
	}
	return 0;
}

// edr_blacklist_filename_add inserts a full exec path into the
// blacklist_filename BPF HASH map. Used for process names longer
// than 15 chars (TASK_COMM_LEN) where comm truncation is unreliable.
static int edr_blacklist_filename_add(struct edr_loader *l, const char *path, __u8 action)
{
	if (!l || l->blacklist_filename_fd < 0 || !path)
		return -EINVAL;
	char key[256] = {0};
	int len = __builtin_strlen(path);
	if (len > 255) len = 255;
	__builtin_memcpy(key, path, len);
	return bpf_map_update_elem(l->blacklist_filename_fd, key, &action, BPF_ANY) ? -errno : 0;
}

// edr_blacklist_filename_clear removes all entries from the
// blacklist_filename BPF HASH map.
static int edr_blacklist_filename_clear(struct edr_loader *l)
{
	if (!l || l->blacklist_filename_fd < 0)
		return -EINVAL;
	char key[256];
	while (bpf_map_get_next_key(l->blacklist_filename_fd, NULL, key) == 0) {
		if (bpf_map_delete_elem(l->blacklist_filename_fd, key))
			return -errno;
	}
	return 0;
}

static int edr_set_ldpreload_kill(struct edr_loader *l, __u8 enabled)
{
	__u32 key = 0;
	if (!l || l->ldpreload_kill_fd < 0)
		return -EINVAL;
	return bpf_map_update_elem(l->ldpreload_kill_fd, &key, &enabled, BPF_ANY) ? -errno : 0;
}

// edr_self_protect_status returns a bitmask indicating which
// self-protection BPF links are active. Bit 1=LSM task_kill,
// 2=LSM ptrace, 3=kprobe kill, 4=kprobe tgkill, 5=kprobe ptrace,
// 6=kprobe pidfd_send_signal.
static unsigned int edr_self_protect_status(struct edr_loader *l)
{
	unsigned int status = 0;
	if (!l) return 0;
	if (l->lsm_task_kill_link)    status |= (1 << 1);
	if (l->lsm_ptrace_link)       status |= (1 << 2);
	if (l->selfprotect_kill_link) status |= (1 << 3);
	if (l->selfprotect_tgkill_link) status |= (1 << 4);
	if (l->selfprotect_ptrace_link) status |= (1 << 5);
	if (l->selfprotect_pidfd_send_signal_link) status |= (1 << 6);
	return status;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// goCtx is a global registry that maps integer handles to *libbpfLoader
// pointers, avoiding the need to pass Go pointers to C (which requires
// runtime.Pinner in Go 1.21+). The C code stores an integer handle and
// passes it back via the ring buffer callback.
var (
	goCtxMu   sync.RWMutex
	goCtxMap  = map[int]*libbpfLoader{}
	goCtxNext int
)

type libbpfLoader struct {
	mu       sync.Mutex
	handle   *C.struct_edr_loader
	out      chan Event
	errs     chan error
	fastOut  chan Event
	stop     chan struct{}
	done     chan struct{}
	loaded   atomic.Bool
	closed   atomic.Bool
	handleID int // index into goCtxMap for C callback
}

// NewLibBPFLoader opens the combined probes.bpf.o / all.bpf.o
// in objDir. The .bpf.o is host-kernel bound; the Makefile
// produces it from the per-probe .bpf.o via `bpftool gen
// object`. NewLibBPFLoader does not load: call Load() to
// start the consumer goroutine.
func NewLibBPFLoader(objDir string) (Loader, error) {
	if objDir == "" {
		return nil, errors.New("bpf: obj_dir is empty")
	}
	path, err := findProbesObject(objDir)
	if err != nil {
		return nil, err
	}
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	l := &libbpfLoader{
		out:     make(chan Event, 256),
		errs:    make(chan error, 16),
		fastOut: make(chan Event, 256),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	rc := C.edr_open(&l.handle, cpath)
	if rc != 0 {
		return nil, fmt.Errorf("bpf: edr_open(%s) rc=%d (CAP_BPF? kernel headers? check libbpf stderr)", path, int(rc))
	}
	// Register in global map so the C callback can look us up by ID
	// without passing a Go pointer to C.
	goCtxMu.Lock()
	goCtxNext++
	l.handleID = goCtxNext
	goCtxMap[l.handleID] = l
	goCtxMu.Unlock()
	C.edr_set_go_ctx(l.handle, unsafe.Pointer(uintptr(l.handleID)))
	return l, nil
}

func (l *libbpfLoader) Load() error {
	if !l.loaded.CompareAndSwap(false, true) {
		return ErrAlreadyLoaded
	}
	go l.pump()
	return nil
}

func (l *libbpfLoader) Events() <-chan Event { return l.out }
func (l *libbpfLoader) Errors() <-chan error { return l.errs }

func (l *libbpfLoader) Close() error {
	if !l.loaded.Load() {
		return ErrNotLoaded
	}
	if !l.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(l.stop)
	<-l.done
	C.edr_close(l.handle)
	l.handle = nil
	goCtxMu.Lock()
	delete(goCtxMap, l.handleID)
	goCtxMu.Unlock()
	return nil
}

// FastEvents returns the fast-path event channel. Exec and
// selfprotect events are duplicated here for low-latency enforcement.
func (l *libbpfLoader) FastEvents() <-chan Event { return l.fastOut }

// SetAgentPID writes the agent PID into the agent_pid BPF map so
// self-protection kprobes can detect kill/ptrace targeting us.
func (l *libbpfLoader) SetAgentPID(pid uint32) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed.Load() {
		return ErrNotLoaded
	}
	rc := C.edr_set_agent_pid(l.handle, C.__u32(pid))
	if rc != 0 {
		return fmt.Errorf("bpf: edr_set_agent_pid rc=%d", int(rc))
	}
	return nil
}

// BlacklistAdd inserts a comm into the blacklist_comm BPF map.
func (l *libbpfLoader) BlacklistAdd(comm string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed.Load() {
		return ErrNotLoaded
	}
	cComm := C.CString(comm)
	defer C.free(unsafe.Pointer(cComm))
	rc := C.edr_blacklist_add(l.handle, cComm, 1)
	if rc != 0 {
		return fmt.Errorf("bpf: edr_blacklist_add(%q) rc=%d", comm, int(rc))
	}
	return nil
}

// BlacklistClear removes all entries from the blacklist_comm BPF
// HASH map so the agent can repopulate it from a new policy.
func (l *libbpfLoader) BlacklistClear() error {
	if l.closed.Load() {
		return ErrNotLoaded
	}
	rc := C.edr_blacklist_clear(l.handle)
	if rc != 0 {
		return fmt.Errorf("bpf: edr_blacklist_clear rc=%d", int(rc))
	}
	return nil
}

// BlacklistFilenameAdd inserts a full exec path into the
// blacklist_filename BPF map.
func (l *libbpfLoader) BlacklistFilenameAdd(path string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed.Load() {
		return ErrNotLoaded
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	rc := C.edr_blacklist_filename_add(l.handle, cPath, 1)
	if rc != 0 {
		return fmt.Errorf("bpf: edr_blacklist_filename_add(%q) rc=%d", path, int(rc))
	}
	return nil
}

// BlacklistFilenameClear removes all entries from the
// blacklist_filename BPF map.
func (l *libbpfLoader) BlacklistFilenameClear() error {
	if l.closed.Load() {
		return ErrNotLoaded
	}
	rc := C.edr_blacklist_filename_clear(l.handle)
	if rc != 0 {
		return fmt.Errorf("bpf: edr_blacklist_filename_clear rc=%d", int(rc))
	}
	return nil
}

// SetLDPreloadKill toggles immediate ring0 kill on LD_PRELOAD detections.
func (l *libbpfLoader) SetLDPreloadKill(enabled bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed.Load() {
		return ErrNotLoaded
	}
	var v C.__u8
	if enabled {
		v = 1
	}
	rc := C.edr_set_ldpreload_kill(l.handle, v)
	if rc != 0 {
		return fmt.Errorf("bpf: edr_set_ldpreload_kill(%t) rc=%d", enabled, int(rc))
	}
	return nil
}

func (l *libbpfLoader) SelfProtectStatus() SelfProtectStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.handle == nil || l.closed.Load() {
		return SelfProtectStatus{}
	}
	bits := C.edr_self_protect_status(l.handle)
	return SelfProtectStatus{
		LSMTaskKill:  (bits & (1 << 1)) != 0,
		LSMPtrace:    (bits & (1 << 2)) != 0,
		KprobeKill:   (bits & (1 << 3)) != 0,
		KprobeTgkill: (bits & (1 << 4)) != 0,
		KprobePtrace: (bits & (1 << 5)) != 0,
		KprobePidfdSendSignal: (bits & (1 << 6)) != 0,
	}
}

func (l *libbpfLoader) pump() {
	defer close(l.done)
	defer close(l.out)
	defer close(l.errs)
	defer close(l.fastOut)
	for {
		if l.closed.Load() {
			return
		}
		rc := int(C.edr_poll(l.handle, 100))
		if l.closed.Load() {
			return
		}
		if rc < 0 {
			select {
			case l.errs <- fmt.Errorf("bpf: edr_poll rc=%d", rc):
			default:
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// edr_deliver_event is called from C (edr_on_event) for every
// ring buffer event. Runs in softirq context: never block.
// Full channel → return -1 (libbpf drops) + surface in
// Errors() per R-O1.
//
//export edr_deliver_event
func edr_deliver_event(ctx unsafe.Pointer, data unsafe.Pointer, size C.size_t) C.int {
	id := int(uintptr(ctx))
	goCtxMu.RLock()
	l := goCtxMap[id]
	goCtxMu.RUnlock()
	if l == nil || l.closed.Load() {
		return -1
	}
	raw := C.GoBytes(data, C.int(size))
	ev, err := ParseEvent(raw)
	if err != nil {
		return 0
	}
	// Duplicate exec, selfprotect, anti-attack, and rootkit events to the
	// fast-path channel for low-latency enforcement.
	if ev.Type == EventExec || ev.Type == EventSelfProtect ||
		ev.Type == EventPtraceEnh || ev.Type == EventLDPreload ||
		ev.Type == EventInstrument || ev.Type == EventPrivesc ||
		ev.Type == EventModuleLoad || ev.Type == EventModuleUnload ||
		ev.Type == EventBPFOp {
		select {
		case l.fastOut <- ev:
		default:
		}
	}
	select {
	case l.out <- ev:
		return 0
	case <-l.stop:
		return -1
	default:
		select {
		case l.errs <- fmt.Errorf("bpf: channel full, dropped type=%v pid=%d", ev.Type, ev.PID):
		default:
		}
		return -1
	}
}

func findProbesObject(objDir string) (string, error) {
	for _, name := range []string{"probes.bpf.o", "all.bpf.o"} {
		p := filepath.Join(objDir, name)
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("bpf: no combined probes.bpf.o / all.bpf.o in %s", objDir)
}
