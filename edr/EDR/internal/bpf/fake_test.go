package bpf

import (
	"errors"
	"testing"
	"time"
)

// fixedNow returns a clock pinned at base, so timestamp assertions
// in tests are exact.
func fixedNow(base time.Time) func() time.Time {
	return func() time.Time { return base }
}

func TestFakeLoader_LoadRejectsSecondCall(t *testing.T) {
	f := NewFakeLoader(nil, 0, time.Now)
	if err := f.Load(); err != nil {
		t.Fatalf("first Load: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := f.Load(); !errors.Is(err, ErrAlreadyLoaded) {
		t.Fatalf("second Load: want ErrAlreadyLoaded, got %v", err)
	}
}

func TestFakeLoader_CloseBeforeLoadReturnsErrNotLoaded(t *testing.T) {
	f := NewFakeLoader(nil, 0, time.Now)
	if err := f.Close(); !errors.Is(err, ErrNotLoaded) {
		t.Fatalf("Close before Load: want ErrNotLoaded, got %v", err)
	}
}

func TestFakeLoader_CloseIsIdempotent(t *testing.T) {
	f := NewFakeLoader(nil, 0, time.Now)
	if err := f.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestFakeLoader_CloseDrainsConsumer(t *testing.T) {
	f := NewFakeLoader(nil, 0, time.Now)
	if err := f.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Events must be closed and Done must be signalled.
	select {
	case _, ok := <-f.Events():
		if ok {
			t.Fatal("Events channel still open after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Events channel did not close after Close")
	}
	select {
	case <-f.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Done channel did not signal after Close")
	}
}

func TestFakeLoader_YieldsPreloadedEventsInOrder(t *testing.T) {
	base := time.Date(2026, 6, 4, 0, 0, 0, 0, time.UTC)
	events := []Event{
		{Type: EventExec, PID: 1, Comm: "a", Filename: "/usr/bin/a"},
		{Type: EventExec, PID: 2, Comm: "b", Filename: "/usr/bin/b"},
		{Type: EventConnect, PID: 3, Comm: "c", DAddr: "1.2.3.4", DPort: 80, Family: 2},
	}
	f := NewFakeLoader(events, 0, fixedNow(base))
	if err := f.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	for i, want := range events {
		select {
		case got := <-f.Events():
			if got.Type != want.Type || got.PID != want.PID || got.Comm != want.Comm {
				t.Errorf("event %d: got %+v, want %+v", i, got, want)
			}
			if got.Filename != want.Filename || got.DAddr != want.DAddr || got.DPort != want.DPort {
				t.Errorf("event %d: payload mismatch: got %+v, want %+v", i, got, want)
			}
			if !got.Timestamp.Equal(base) {
				t.Errorf("event %d: timestamp not frozen at base: got %v", i, got.Timestamp)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("event %d: timed out", i)
		}
	}
}

func TestFakeLoader_PreservesExplicitTimestamps(t *testing.T) {
	pre := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	now := time.Date(2026, 6, 4, 0, 0, 0, 0, time.UTC)
	events := []Event{{Type: EventExec, PID: 7, Timestamp: pre}}
	f := NewFakeLoader(events, 0, fixedNow(now))
	if err := f.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	got := <-f.Events()
	if !got.Timestamp.Equal(pre) {
		t.Fatalf("explicit timestamp overwritten: got %v, want %v", got.Timestamp, pre)
	}
}

func TestFakeLoader_InjectAfterLoad(t *testing.T) {
	f := NewFakeLoader(nil, 0, time.Now)
	if err := f.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	f.Inject(Event{Type: EventExec, PID: 99, Comm: "injected"})
	select {
	case got := <-f.Events():
		if got.PID != 99 || got.Comm != "injected" || got.Type != EventExec {
			t.Errorf("injected event mismatch: %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("injected event not delivered")
	}
}

func TestFakeLoader_InjectErrorReachesErrorsChannel(t *testing.T) {
	f := NewFakeLoader(nil, 0, time.Now)
	if err := f.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	sentinel := errors.New("ring buffer overrun")
	f.InjectError(sentinel)
	select {
	case got := <-f.Errors():
		if !errors.Is(got, sentinel) {
			t.Errorf("errors: got %v, want %v", got, sentinel)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("injected error not delivered")
	}
}

func TestFakeLoader_InjectErrorDropsOnFull(t *testing.T) {
	// errs buffer is 16; pump goroutine is alive but Errors() is
	// not drained here. The 17th call must not block — that is
	// the whole point of treating the sink as best-effort (R-O1).
	f := NewFakeLoader(nil, 0, time.Now)
	if err := f.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	for i := 0; i < 64; i++ {
		f.InjectError(errors.New("noise"))
	}
}

func TestFakeLoader_InjectBeforeLoadIsNoop(t *testing.T) {
	f := NewFakeLoader(nil, 0, time.Now)
	f.Inject(Event{Type: EventExec, PID: 1})
	// Nothing asserted directly: if Inject blocked or panicked
	// before Load, the test would hang or fail here.
	if err := f.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	// Pump should have nothing to do; close and move on.
}

func TestEventType_String(t *testing.T) {
	cases := map[EventType]string{
		EventUnknown:  "unknown",
		EventExec:     "exec",
		EventFork:     "fork",
		EventExit:     "exit",
		EventConnect:  "connect",
		EventType(99): "unknown",
	}
	for in, want := range cases {
		if got := in.String(); got != want {
			t.Errorf("%d: got %q, want %q", in, got, want)
		}
	}
}
