package collector

import (
	"sync"
	"time"

	"edr/internal/bpf"
)

// BPFHealth is the operator-facing observability surface of the
// ring0 path. It is updated every Snapshot and is safe to read
// concurrently with Snapshot (R-K2).
type BPFHealth struct {
	Attached      bool      `json:"attached"`
	EventsDrained uint64    `json:"events_drained"`
	OverloadDrops uint64    `json:"overload_drops"`
	LastErrorAt   time.Time `json:"last_error_at,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
}

// MergedCollector composes a ProcfsCollector (ring3, always on)
// with a bpf.Loader (ring0, opt-in). On Snapshot it returns
// the union of both, with the rule "ring0 wins on conflict":
// the kernel tracepoint data is fresher than /proc (which lags
// by milliseconds during exec), so a matching Process's Name
// and Path are overridden by the BPF event.
//
// The collector never blocks on BPF. Events() is drained in a
// non-blocking loop and anything that arrives after the channel
// is empty stays queued for the next Snapshot. A slow consumer
// therefore sees ring3 data first and gradually catches up on
// ring0.
type MergedCollector struct {
	procfs *ProcfsCollector
	bpf    bpf.Loader

	mu      sync.Mutex
	drained uint64
	drops   uint64
	errs    []error
	lastErr error
	health  BPFHealth
}

// NewMergedCollector wires the two sources. b may be nil, in
// which case the collector behaves identically to the procfs
// collector alone and BPFHealth().Attached stays false.
func NewMergedCollector(procfs *ProcfsCollector, b bpf.Loader) *MergedCollector {
	return &MergedCollector{
		procfs: procfs,
		bpf:    b,
		health: BPFHealth{Attached: b != nil},
	}
}

// Snapshot returns the merged snapshot. The procfs error, if
// any, is recorded and returned; BPF errors do not fail the
// snapshot — they are accumulated in BPFHealth and exposed via
// Errors() for the agent's /healthz (R-O1).
func (m *MergedCollector) Snapshot() (Snapshot, error) {
	snap, err := m.procfs.Snapshot()
	if err != nil {
		m.recordErr(err)
	}
	if m.bpf != nil {
		m.drainBPF(&snap)
	}
	return snap, err
}

// BPFHealth returns a copy of the current ring0 observability
// surface. Safe to call concurrently with Snapshot.
func (m *MergedCollector) BPFHealth() BPFHealth {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.health
}

// Errors returns and clears the non-fatal errors observed since
// the last call. The agent surfaces these in /healthz and in
// audit events (R-O1).
func (m *MergedCollector) Errors() []error {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.errs
	m.errs = nil
	return out
}

// LastError returns the most recent snapshot error and clears
// it. Returns nil if no error has been recorded since the last
// call.
func (m *MergedCollector) LastError() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.lastErr
	m.lastErr = nil
	return e
}

// Loader exposes the underlying bpf.Loader so the agent can
// own its lifecycle (Load at startup, Close at shutdown) and
// drain its Errors() channel.
func (m *MergedCollector) Loader() bpf.Loader { return m.bpf }

func (m *MergedCollector) recordErr(err error) {
	if err == nil {
		return
	}
	m.mu.Lock()
	m.lastErr = err
	m.errs = append(m.errs, err)
	m.health.LastError = err.Error()
	m.health.LastErrorAt = time.Now().UTC()
	m.mu.Unlock()
}

// drainBPF reads every event currently buffered on the BPF
// channel without blocking, then applies them. Events that
// arrive after the channel is fully drained remain queued for
// the next Snapshot.
func (m *MergedCollector) drainBPF(snap *Snapshot) {
	events := m.bpf.Events()
	if events == nil {
		return
	}
	var batch []bpf.Event
	for {
		select {
		case e, ok := <-events:
			if !ok {
				m.applyEvents(snap, batch)
				m.markLoaderClosed()
				return
			}
			batch = append(batch, e)
		default:
			m.applyEvents(snap, batch)
			return
		}
	}
}

// applyEvents mutates snap in place: Exec events override or
// append a Process; Connect events append a Connection. Fork
// and Exit are observational only — the next /proc scan will
// reflect the new or removed process.
func (m *MergedCollector) applyEvents(snap *Snapshot, events []bpf.Event) {
	if len(events) == 0 {
		return
	}
	procByPID := make(map[int]int, len(snap.Processes))
	for i, p := range snap.Processes {
		procByPID[p.PID] = i
	}
	for _, e := range events {
		switch e.Type {
		case bpf.EventExec:
			m.applyExec(snap, &procByPID, e)
		case bpf.EventConnect:
			m.applyConnect(snap, e)
		}
	}
	m.mu.Lock()
	m.drained += uint64(len(events))
	m.health.EventsDrained = m.drained
	m.mu.Unlock()
}

func (m *MergedCollector) applyExec(snap *Snapshot, procByPID *map[int]int, e bpf.Event) {
	pid := int(e.PID)
	if idx, ok := (*procByPID)[pid]; ok {
		p := &snap.Processes[idx]
		// Ring0 wins on conflict. Cmdline is left untouched:
		// ring0's tracepoint only carries argv[0], while
		// /proc/PID/cmdline has the full vector.
		if e.Comm != "" {
			p.Name = e.Comm
		}
		if e.Filename != "" {
			p.Path = e.Filename
		}
		return
	}
	p := Process{
		PID:     pid,
		Name:    e.Comm,
		Path:    e.Filename,
		Cmdline: e.Comm,
	}
	snap.Processes = append(snap.Processes, p)
	(*procByPID)[pid] = len(snap.Processes) - 1
}

func (m *MergedCollector) applyConnect(snap *Snapshot, e bpf.Event) {
	snap.Connections = append(snap.Connections, Connection{
		Protocol:   protocolFromFamily(e.Family),
		RemoteAddr: e.DAddr,
		RemotePort: int(e.DPort),
	})
}

func (m *MergedCollector) markLoaderClosed() {
	m.mu.Lock()
	m.health.Attached = false
	m.mu.Unlock()
}

func protocolFromFamily(family uint8) string {
	switch family {
	case 2:
		return "tcp"
	case 10:
		return "tcp6"
	case 1:
		return "unix"
	default:
		return "unknown"
	}
}
