package bpf

import (
	"context"
	"errors"
)

// Loader loads BPF programs, attaches them to tracepoints/kprobes,
// and exposes the resulting event stream. Implementations are
// expected to be safe to Close from any goroutine and to drain
// their goroutines before Close returns (R-K1).
type Loader interface {
	// Load pins the BPF object, attaches probes, and starts the
	// consumer goroutine. Calling Load twice without an intervening
	// Close returns ErrAlreadyLoaded.
	Load() error

	// Events is the read-side of the kernel event stream. The channel
	// is closed when Close is called or the loader's context ends.
	Events() <-chan Event

	// Errors is a non-fatal error sink (lost samples, ring buffer
	// overruns, periodic read errors). The channel is closed when
	// Close is called. Implementations should drop on overflow rather
	// than block the producer.
	Errors() <-chan error

	// Close detaches probes, releases resources, and waits for the
	// consumer goroutine to exit. Safe to call multiple times.
	Close() error
}

// ErrAlreadyLoaded is returned by Load when the loader has already
// been started and not yet closed.
var ErrAlreadyLoaded = errors.New("bpf loader already loaded")

// ErrNotLoaded is returned by Close when it is called before a
// successful Load. It is also returned by Events/Errors/Inject
// helpers on implementations that expose them.
var ErrNotLoaded = errors.New("bpf loader not loaded")

// MapFiller is an optional interface implemented by BPF loaders that
// support populating BPF maps from userspace. The agent uses this to
// configure agent_pid, blacklist_comm, and blacklist_filename maps
// at startup.
type MapFiller interface {
	SetAgentPID(pid uint32) error
	BlacklistAdd(comm string) error
	BlacklistClear() error
	BlacklistFilenameAdd(path string) error
	BlacklistFilenameClear() error
	SetLDPreloadKill(enabled bool) error
	SetBpfGuard(enabled bool) error // v0.16: toggle BPF_MAP_UPDATE_ELEM guard

	// v0.8: network ring0 blocking maps
	SetNetBlacklistEnabled(enabled bool) error
	NetBlacklistIPAdd(ip string) error
	NetBlacklistIPClear() error
	NetBlacklistPortAdd(port uint16) error
	NetBlacklistPortClear() error
}

// FastPathLoader is implemented by loaders that support a dedicated
// fast-path event channel for low-latency enforcement. Exec and
// selfprotect events are duplicated to this channel so the agent can
// act on them within milliseconds rather than waiting for the 5s poll
// cycle.
type FastPathLoader interface {
	Loader
	FastEvents() <-chan Event
}

// Done blocks until the loader's consumer goroutine has exited.
// It exists for tests and for the agent's Run loop so that
// shutdown order is deterministic (R-K1). Implementations may
// return a channel that is already closed when the loader has
// never been started.
type DoneAware interface {
	Done() <-chan struct{}
}

// SelfProtectStatus reports which self-protection BPF programs
// are successfully attached. Used to populate BPFHealth metrics.
type SelfProtectStatus struct {
	LSMTaskKill  bool
	LSMPtrace    bool
	KprobeKill   bool
	KprobeTgkill bool
	KprobePtrace bool
	KprobePidfdSendSignal bool
	BpfGuard     bool // v0.16: blocks BPF_MAP_UPDATE_ELEM from non-edr-agent
}

// SelfProtectReporter is implemented by loaders that can report
// self-protection BPF link attachment status.
type SelfProtectReporter interface {
	SelfProtectStatus() SelfProtectStatus
}

// ctxDone turns a context cancellation into a done-style signal
// without forcing every Loader to take a context. Callers that
// want context wiring can do it in the merge layer.
func ctxDone(ctx context.Context) <-chan struct{} {
	if ctx == nil {
		return nil
	}
	return ctx.Done()
}
