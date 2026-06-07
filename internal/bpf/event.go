// Package bpf hosts the v0.2 eBPF telemetry path. The package boundary
// is intentionally narrow: it owns the kernel-event type and the
// Loader interface that the agent depends on. Concrete loaders
// (libbpf, cilium/ebpf, fake) live alongside as separate files so
// that production builds and unit tests can pick the right one
// without leaking build tags across the tree.
package bpf

import "time"

// EventType is the small set of tracepoints v0.2 cares about.
// New variants must be appended, not reordered, so that the numeric
// value stays stable across releases (R-L3 — schema stability).
type EventType uint8

const (
	EventUnknown EventType = iota
	EventExec
	EventFork
	EventExit
	EventConnect
	EventSelfProtect
	EventPtraceEnh   // v0.4: enhanced ptrace detection (all calls, not just agent-targeting)
	EventLDPreload   // v0.4: LD_PRELOAD injection detected at execve
	EventInstrument  // v0.4: suspicious shared library load detected
)

func (t EventType) String() string {
	switch t {
	case EventExec:
		return "exec"
	case EventFork:
		return "fork"
	case EventExit:
		return "exit"
	case EventConnect:
		return "connect"
	case EventSelfProtect:
		return "selfprotect"
	case EventPtraceEnh:
		return "ptrace_enh"
	case EventLDPreload:
		return "ldpreload"
	case EventInstrument:
		return "instrument"
	default:
		return "unknown"
	}
}

// Event is the kernel-side observation that bpf loaders produce.
// It is mapped into collector.Snapshot by the merge layer (Step 2);
// nothing in this package is allowed to import the collector or
// eventlog packages, so the merge direction is one-way.
type Event struct {
	Type      EventType
	Timestamp time.Time
	PID       uint32
	PPID      uint32
	TGID      uint32
	UID       uint32
	Reserved  uint32 // ptrace_enh: ptrace request type (PTRACE_TRACEME=0, etc.)
	Comm      string
	Filename  string // exec: argv[0] / resolved binary path; ldpreload: LD_PRELOAD value; instrument: library path
	DAddr     string // connect: remote address (IPv4 dotted, IPv6 bracketed)
	DPort     uint16 // connect: remote port (host byte order)
	Family    uint8  // connect: AF_INET / AF_INET6
}
