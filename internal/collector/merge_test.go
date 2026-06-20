package collector

import (
	"errors"
	"testing"
	"time"

	"edr/internal/bpf"
)

// waitFor polls Snapshot until pred returns true. The BPF pump
// goroutine is scheduled by the Go runtime, so a freshly-loaded
// FakeLoader may not have pushed events onto its out channel
// by the time the test calls Snapshot. The loop is bounded by
// a 2-second deadline.
func waitFor(t *testing.T, mc *MergedCollector, pred func(Snapshot) bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snap, _ := mc.Snapshot()
		if pred(snap) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	snap, _ := mc.Snapshot()
	t.Fatalf("waitFor: timeout, last snapshot: %+v", snap)
}

func TestMergedCollector_NilBPFBehavesLikeProcfs(t *testing.T) {
	mc := NewMergedCollector(&ProcfsCollector{}, nil)
	snap, err := mc.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if h := mc.BPFHealth(); h.Attached || h.EventsDrained != 0 {
		t.Errorf("BPFHealth with nil loader: %+v", h)
	}
	_ = snap
}

func TestMergedCollector_ExecEventOverridesExistingProcess(t *testing.T) {
	mc := &MergedCollector{health: BPFHealth{Attached: true}}
	snap := Snapshot{Processes: []Process{{PID: 42, Name: "old", Path: "/old/path", Cmdline: "/old/path arg1"}}}
	mc.applyEvents(&snap, []bpf.Event{
		{Type: bpf.EventExec, PID: 42, Comm: "new", Filename: "/new/path"},
	})
	if len(snap.Processes) != 1 {
		t.Fatalf("expected 1 process, got %d", len(snap.Processes))
	}
	p := snap.Processes[0]
	if p.Name != "new" {
		t.Errorf("Name: want %q, got %q", "new", p.Name)
	}
	if p.Path != "/new/path" {
		t.Errorf("Path: want %q, got %q", "/new/path", p.Path)
	}
	if p.Cmdline != "/old/path arg1" {
		t.Errorf("Cmdline should not be overwritten: got %q", p.Cmdline)
	}
}

func TestMergedCollector_ExecEventAddsProcessIfMissing(t *testing.T) {
	mc := &MergedCollector{health: BPFHealth{Attached: true}}
	snap := Snapshot{}
	mc.applyEvents(&snap, []bpf.Event{
		{Type: bpf.EventExec, PID: 100, Comm: "ls", Filename: "/bin/ls"},
	})
	if len(snap.Processes) != 1 {
		t.Fatalf("expected 1 process, got %d", len(snap.Processes))
	}
	p := snap.Processes[0]
	if p.PID != 100 || p.Name != "ls" || p.Path != "/bin/ls" {
		t.Errorf("appended process: %+v", p)
	}
}

func TestMergedCollector_ConnectEventAppendsConnection(t *testing.T) {
	mc := &MergedCollector{health: BPFHealth{Attached: true}}
	snap := Snapshot{}
	mc.applyEvents(&snap, []bpf.Event{
		{Type: bpf.EventConnect, PID: 7, Comm: "curl", DAddr: "1.2.3.4", DPort: 443, Family: 2},
		{Type: bpf.EventConnect, PID: 8, Comm: "curl6", DAddr: "::1", DPort: 80, Family: 10},
	})
	if len(snap.Connections) != 2 {
		t.Fatalf("expected 2 connections, got %d", len(snap.Connections))
	}
	if snap.Connections[0].Protocol != "tcp" || snap.Connections[0].RemoteAddr != "1.2.3.4" || snap.Connections[0].RemotePort != 443 {
		t.Errorf("v4 connection: %+v", snap.Connections[0])
	}
	if snap.Connections[1].Protocol != "tcp6" || snap.Connections[1].RemoteAddr != "::1" || snap.Connections[1].RemotePort != 80 {
		t.Errorf("v6 connection: %+v", snap.Connections[1])
	}
}

func TestMergedCollector_ForkAndExitAreObservational(t *testing.T) {
	mc := &MergedCollector{health: BPFHealth{Attached: true}}
	snap := Snapshot{Processes: []Process{{PID: 1, Name: "init"}}}
	mc.applyEvents(&snap, []bpf.Event{
		{Type: bpf.EventFork, PID: 100, PPID: 1},
		{Type: bpf.EventExit, PID: 1},
	})
	if len(snap.Processes) != 1 {
		t.Errorf("Fork/Exit should not mutate Processes: %+v", snap.Processes)
	}
	if len(snap.Connections) != 0 {
		t.Errorf("Fork/Exit should not mutate Connections: %+v", snap.Connections)
	}
}

func TestMergedCollector_EmptyBatchIsNoop(t *testing.T) {
	mc := &MergedCollector{health: BPFHealth{Attached: true}}
	before := BPFHealth{Attached: true, EventsDrained: 0}
	if mc.BPFHealth() != before {
		t.Fatalf("starting BPFHealth: %+v", mc.BPFHealth())
	}
	mc.applyEvents(&Snapshot{}, nil)
	if h := mc.BPFHealth(); h.EventsDrained != 0 {
		t.Errorf("empty batch must not bump counter: %+v", h)
	}
}

func TestMergedCollector_ApplyEventsBumpsCounter(t *testing.T) {
	mc := &MergedCollector{health: BPFHealth{Attached: true}}
	mc.applyEvents(&Snapshot{}, []bpf.Event{
		{Type: bpf.EventExec, PID: 1, Comm: "a"},
		{Type: bpf.EventExec, PID: 2, Comm: "b"},
		{Type: bpf.EventConnect, PID: 3, DAddr: "1.1.1.1", DPort: 1, Family: 2},
	})
	if h := mc.BPFHealth(); h.EventsDrained != 3 {
		t.Errorf("EventsDrained: want 3, got %d", h.EventsDrained)
	}
}

func TestMergedCollector_FullSnapshotDrainsBPFChannel(t *testing.T) {
	bpfl := bpf.NewFakeLoader([]bpf.Event{
		{Type: bpf.EventExec, PID: 4242, Comm: "fake", Filename: "/usr/bin/fake"},
		{Type: bpf.EventConnect, PID: 4242, Comm: "fake", DAddr: "9.9.9.9", DPort: 53, Family: 2},
	}, 0, time.Now)
	if err := bpfl.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { _ = bpfl.Close() })

	mc := NewMergedCollector(&ProcfsCollector{}, bpfl)
	waitFor(t, mc, func(s Snapshot) bool {
		return len(s.Processes) > 0 || len(s.Connections) > 0
	})
	if h := mc.BPFHealth(); !h.Attached || h.EventsDrained == 0 {
		t.Errorf("BPFHealth after drain: %+v", h)
	}
}

func TestMergedCollector_NonBlockingDrainDoesNotStallOnSlowBPF(t *testing.T) {
	// interval=1h means the pump will not deliver the
	// preloaded event during the test. The merged collector's
	// drain must not wait for the pump. We compare a baseline
	// (no BPF) against the same Snapshot loop with BPF attached
	// but idle: the difference should be near zero. A 50ms
	// slack absorbs scheduler jitter without hiding a real
	// stall.
	procfs := &ProcfsCollector{}
	mcNoBPF := NewMergedCollector(procfs, nil)

	bpfl := bpf.NewFakeLoader([]bpf.Event{
		{Type: bpf.EventExec, PID: 1, Comm: "a"},
	}, time.Hour, time.Now)
	if err := bpfl.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { _ = bpfl.Close() })
	mcWithBPF := NewMergedCollector(procfs, bpfl)

	// Warm up the procfs scan caches.
	_, _ = mcNoBPF.Snapshot()
	_, _ = mcWithBPF.Snapshot()

	const calls = 5
	startNo := time.Now()
	for i := 0; i < calls; i++ {
		if _, err := mcNoBPF.Snapshot(); err != nil {
			t.Fatalf("Snapshot noBPF %d: %v", i, err)
		}
	}
	tNo := time.Since(startNo)

	startBPF := time.Now()
	for i := 0; i < calls; i++ {
		if _, err := mcWithBPF.Snapshot(); err != nil {
			t.Fatalf("Snapshot withBPF %d: %v", i, err)
		}
	}
	tBPF := time.Since(startBPF)

	if slack := tBPF - tNo - 50*time.Millisecond; slack > 0 {
		t.Errorf("drainBPF appears to block: tNo=%v tBPF=%v slack=%v", tNo, tBPF, slack)
	}
}

func TestMergedCollector_ErrorsRoundTrip(t *testing.T) {
	mc := &MergedCollector{health: BPFHealth{Attached: true}}
	sentinel := errors.New("procfs read failed")
	mc.recordErr(sentinel)
	if got := mc.LastError(); !errors.Is(got, sentinel) {
		t.Errorf("LastError: want %v, got %v", sentinel, got)
	}
	if got := mc.LastError(); got != nil {
		t.Errorf("LastError after consume: want nil, got %v", got)
	}
	errs := mc.Errors()
	if len(errs) != 1 || !errors.Is(errs[0], sentinel) {
		t.Errorf("Errors: want [%v], got %v", sentinel, errs)
	}
	if got := mc.Errors(); len(got) != 0 {
		t.Errorf("Errors after consume: want [], got %v", got)
	}
}

func TestMergedCollector_LoaderExposesUnderlying(t *testing.T) {
	bpfl := bpf.NewFakeLoader(nil, 0, time.Now)
	mc := NewMergedCollector(&ProcfsCollector{}, bpfl)
	if mc.Loader() != bpf.Loader(bpfl) {
		t.Errorf("Loader() should return the same instance")
	}
}

func TestProtocolFromFamily(t *testing.T) {
	cases := map[uint8]string{
		0:  "unknown",
		1:  "unix",
		2:  "tcp",
		10: "tcp6",
		42: "unknown",
	}
	for in, want := range cases {
		if got := protocolFromFamily(in); got != want {
			t.Errorf("family %d: want %q, got %q", in, want, got)
		}
	}
}
