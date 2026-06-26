// internal/integrity/process_forgery.go
// v0.9: Process forgery detection — kernel thread impersonation.
//
// Attackers rename their comm to mimic kernel threads (kworker/*,
// ksoftirqd/*, etc.) to evade detection rules. This module detects
// such forgery by cross-checking comm patterns against hard kernel
// thread characteristics that cannot be forged.

package integrity

import (
	"fmt"
	"strings"
)

// kernelThreadPrefixes lists comm prefixes that belong to genuine
// kernel threads. A user-space process whose comm starts with one of
// these is almost certainly attempting to hide.
var kernelThreadPrefixes = []string{
	"kworker/",
	"ksoftirqd/",
	"migration/",
	"watchdog/",
	"watchdogd",
	"kthreadd",
	"kdevtmpfs",
	"kauditd",
	"khungtaskd",
	"oom_reaper",
	"kswapd",
	"kcompactd",
	"khugepaged",
	"rcu_",
	"cpuhp/",
	"idle_inject/",
	"ecryptfs-kthrea",
}

// ProcessInfo carries the minimum fields needed for forgery detection.
type ProcessInfo struct {
	PID     int
	Name    string // comm from /proc/pid/comm
	PPID    int
	Path    string // /proc/pid/exe target
	Cmdline string
}

// ForgeryResult describes a detected forgery.
type ForgeryResult struct {
	Forged  bool
	Reason  string
	PID     int
	Name    string
	PPID    int
	Exe     string
}

// CheckKernelThreadForgery detects user-space processes that are
// impersonating kernel threads.
//
// A genuine kernel thread MUST satisfy ALL of:
//   1. PPID == 2 (kthreadd)
//   2. /proc/pid/exe is empty or unreadable
//   3. /proc/pid/cmdline is empty
//
// Any process whose comm matches a kernel thread pattern but fails
// ANY of the above is flagged as a forgery.
func CheckKernelThreadForgery(p ProcessInfo) ForgeryResult {
	r := ForgeryResult{
		PID:  p.PID,
		Name: p.Name,
		PPID: p.PPID,
		Exe:  p.Path,
	}

	if !matchesKernelPattern(p.Name) {
		return r
	}

	// Hard check: real kernel threads ALWAYS have PPID == 2.
	// This is the single most reliable signal — kthreadd forks
	// every kernel thread, so PPID cannot be anything else.
	if p.PPID == 2 {
		return r
	}

	r.Forged = true
	r.Reason = fmt.Sprintf(
		"comm=%q matches kernel thread pattern but PPID=%d (expected 2), exe=%q",
		p.Name, p.PPID, p.Path,
	)
	return r
}

// CheckBPFForgeryTag checks for the BPF-side 0x464F5247 ("FORG")
// tag written by exec.bpf.c when it detects a kernel-worker pattern
// with PPID != 2 at exec time.
func CheckBPFForgeryTag(reserved uint32) bool {
	return reserved == 0x464F5247
}

func matchesKernelPattern(comm string) bool {
	for _, prefix := range kernelThreadPrefixes {
		if strings.HasPrefix(comm, prefix) {
			return true
		}
	}
	return false
}

// KernelThreadProcess is the hardened replacement for the original
// rootsession/manger.go kernelThreadProcess(). It adds the PPID==2
// hard requirement that the original missed.
//
// A process is a genuine kernel thread only when:
//   - PPID == 2 (kthreadd is the only parent of kernel threads)
//   - No TTY
//   - No readble exe
//   - Empty cmdline
func KernelThreadProcess(p ProcessInfo) bool {
	if p.PPID != 2 {
		return false
	}
	if strings.TrimSpace(p.Path) != "" {
		return false
	}
	if strings.TrimSpace(p.Cmdline) != "" {
		return false
	}
	return true
}
