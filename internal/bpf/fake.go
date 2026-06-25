package bpf

import (
	"sync"
	"sync/atomic"
	"time"
)

// FakeLoader is an in-memory Loader used by unit tests and by
// dev/CI environments where CAP_BPF is unavailable. It is fully
// deterministic: events are taken from the slice supplied at
// construction (in order), then any subsequent Inject calls, and
// emitted on Events() with a configurable cadence. Timestamps
// are assigned from the time source only when an event has a
// zero Timestamp, so tests can pin them precisely (R-K4).
type FakeLoader struct {
	mu       sync.Mutex
	pending  []Event
	cursor   int
	interval time.Duration
	now      func() time.Time

	out     chan Event
	errs    chan error
	fastOut chan Event
	stop    chan struct{}
	wakeup  chan struct{}
	done    chan struct{}

	loaded atomic.Bool
	closed atomic.Bool
}

// NewFakeLoader returns a FakeLoader that, after Load, drains the
// given events in order. If interval > 0 the pump pauses for that
// duration between yields; interval == 0 means "yield as fast as
// the consumer reads". ts supplies Timestamps for events that
// arrive with Timestamp.IsZero(); nil falls back to time.Now.
func NewFakeLoader(events []Event, interval time.Duration, ts func() time.Time) *FakeLoader {
	if ts == nil {
		ts = time.Now
	}
	return &FakeLoader{
		pending:  append([]Event(nil), events...),
		interval: interval,
		now:      ts,
		out:      make(chan Event, 32),
		errs:     make(chan error, 16),
		fastOut:  make(chan Event, 32),
		stop:     make(chan struct{}),
		wakeup:   make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
}

// Load satisfies Loader. It returns ErrAlreadyLoaded on the second
// call without an intervening Close.
func (f *FakeLoader) Load() error {
	if !f.loaded.CompareAndSwap(false, true) {
		return ErrAlreadyLoaded
	}
	go f.pump()
	return nil
}

// Events returns the read side of the in-memory event stream.
func (f *FakeLoader) Events() <-chan Event { return f.out }

// Errors returns the read side of the non-fatal error sink.
func (f *FakeLoader) Errors() <-chan error { return f.errs }

// Done blocks until the consumer goroutine has exited.
func (f *FakeLoader) Done() <-chan struct{} { return f.done }

// FastEvents returns the fast-path event channel for testing.
func (f *FakeLoader) FastEvents() <-chan Event { return f.fastOut }

// SetAgentPID is a no-op stub for the FakeLoader.
func (f *FakeLoader) SetAgentPID(pid uint32) error { return nil }

// SetBpfGuard is a no-op stub for the FakeLoader.
func (f *FakeLoader) SetBpfGuard(enabled bool) error { return nil }

// BlacklistAdd is a no-op stub for the FakeLoader.
func (f *FakeLoader) BlacklistAdd(comm string) error { return nil }

// BlacklistClear is a no-op stub for the FakeLoader.
func (f *FakeLoader) BlacklistClear() error { return nil }

// BlacklistFilenameAdd is a no-op stub for the FakeLoader.
func (f *FakeLoader) BlacklistFilenameAdd(path string) error { return nil }

// BlacklistFilenameClear is a no-op stub for the FakeLoader.
func (f *FakeLoader) BlacklistFilenameClear() error { return nil }

// SetLDPreloadKill is a no-op stub for the FakeLoader.
func (f *FakeLoader) SetLDPreloadKill(enabled bool) error { return nil }

// SetNetBlacklistEnabled is a no-op stub for the FakeLoader.
func (f *FakeLoader) SetNetBlacklistEnabled(enabled bool) error { return nil }

// NetBlacklistIPAdd is a no-op stub for the FakeLoader.
func (f *FakeLoader) NetBlacklistIPAdd(ip string) error { return nil }

// NetBlacklistIPClear is a no-op stub for the FakeLoader.
func (f *FakeLoader) NetBlacklistIPClear() error { return nil }

// NetBlacklistPortAdd is a no-op stub for the FakeLoader.
func (f *FakeLoader) NetBlacklistPortAdd(port uint16) error { return nil }

// NetBlacklistPortClear is a no-op stub for the FakeLoader.
func (f *FakeLoader) NetBlacklistPortClear() error { return nil }

func (f *FakeLoader) SelfProtectStatus() SelfProtectStatus {
	return SelfProtectStatus{}
}

// Inject enqueues an event after the currently-pending queue. It
// is a no-op if the loader has not been Loaded, or if it has been
// Closed. Safe to call from any goroutine.
func (f *FakeLoader) Inject(e Event) {
	if f.closed.Load() || !f.loaded.Load() {
		return
	}
	f.mu.Lock()
	f.pending = append(f.pending, e)
	f.mu.Unlock()
	select {
	case f.wakeup <- struct{}{}:
	default:
	}
}

// InjectError pushes a non-fatal error onto the Errors channel.
// Overflow is dropped silently by design (R-O1: the sink is for
// observability, not for delivery guarantees).
func (f *FakeLoader) InjectError(err error) {
	if err == nil || f.closed.Load() || !f.loaded.Load() {
		return
	}
	select {
	case f.errs <- err:
	default:
	}
}

// Close stops the consumer goroutine and closes Events/Errors.
// Returns ErrNotLoaded if the loader was never started, nil
// otherwise (including on repeat calls).
func (f *FakeLoader) Close() error {
	if !f.loaded.Load() {
		return ErrNotLoaded
	}
	if !f.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(f.stop)
	<-f.done
	return nil
}

func (f *FakeLoader) pump() {
	defer close(f.done)
	defer close(f.out)
	defer close(f.errs)
	defer close(f.fastOut)
	for {
		f.mu.Lock()
		if f.cursor >= len(f.pending) {
			f.mu.Unlock()
			select {
			case <-f.wakeup:
				continue
			case <-f.stop:
				return
			}
		}
		e := f.pending[f.cursor]
		f.cursor++
		f.mu.Unlock()
		if e.Timestamp.IsZero() {
			e.Timestamp = f.now().UTC()
		}
		if f.interval > 0 {
			select {
			case <-time.After(f.interval):
			case <-f.stop:
				return
			}
		}
		select {
		case f.out <- e:
		case <-f.stop:
			return
		}
		if e.Type == EventExec || e.Type == EventSelfProtect ||
			e.Type == EventPtraceEnh || e.Type == EventLDPreload ||
			e.Type == EventInstrument || e.Type == EventPrivesc ||
			e.Type == EventModuleLoad || e.Type == EventModuleUnload ||
			e.Type == EventBPFOp {
			select {
			case f.fastOut <- e:
			default:
			}
		}
	}
}
