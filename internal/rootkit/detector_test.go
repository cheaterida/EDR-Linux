package rootkit

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"edr/internal/bpf"
	"edr/internal/collector"
)

func TestDetectHiddenProcesses(t *testing.T) {
	procRoot := t.TempDir()
	// Create two fake /proc entries.
	mustMkdir(t, filepath.Join(procRoot, "1"))
	mustMkdir(t, filepath.Join(procRoot, "2"))

	// BPF saw PID 1, 2, and 3 (3 hidden).
	loader := bpf.NewFakeLoader([]bpf.Event{
		{Type: bpf.EventExec, PID: 1, Comm: "init"},
		{Type: bpf.EventExec, PID: 2, Comm: "kthre"},
		{Type: bpf.EventExec, PID: 3, Comm: "hidden"},
	}, 0, nil)
	if err := loader.Load(); err != nil {
		t.Fatal(err)
	}
	defer loader.Close()

	mc := collector.NewMergedCollector(&collector.ProcfsCollector{ProcRoot: procRoot}, loader)
	// Drain BPF events into the collector's seenPIDs cache. FakeLoader
	// emits asynchronously, so poll briefly.
	var seen map[int]time.Time
	for i := 0; i < 50; i++ {
		if _, err := mc.Snapshot(); err != nil {
			t.Fatal(err)
		}
		seen = mc.SeenPIDs()
		if len(seen) >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(seen) < 3 {
		t.Fatalf("expected 3 seen PIDs, got %d", len(seen))
	}

	d := &Detector{Collector: mc, ProcRoot: procRoot, Grace: time.Second}
	findings, err := d.DetectHiddenProcesses()
	if err != nil {
		t.Fatalf("DetectHiddenProcesses error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 hidden process finding, got %d", len(findings))
	}
	if findings[0].Subject["pid"] != 3 {
		t.Fatalf("expected hidden pid 3, got %v", findings[0].Subject["pid"])
	}
	if findings[0].Action != "observe" {
		t.Fatalf("expected observe action, got %q", findings[0].Action)
	}
}

func TestDetectHiddenProcessesSkipsExitedTreeNode(t *testing.T) {
	procRoot := t.TempDir()
	mustMkdir(t, filepath.Join(procRoot, "1"))
	pidDir := filepath.Join(procRoot, "10")
	mustMkdir(t, pidDir)
	mustWrite(t, filepath.Join(pidDir, "comm"), "short\n")
	mustWrite(t, filepath.Join(pidDir, "cmdline"), "short\x00")
	mustWrite(t, filepath.Join(pidDir, "stat"), "10 (short) S 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 123 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")

	loader := bpf.NewFakeLoader([]bpf.Event{
		{Type: bpf.EventExec, PID: 10, Comm: "short"},
	}, 0, nil)
	if err := loader.Load(); err != nil {
		t.Fatal(err)
	}
	defer loader.Close()

	mc := collector.NewMergedCollector(&collector.ProcfsCollector{ProcRoot: procRoot}, loader)
	for i := 0; i < 20; i++ {
		if _, err := mc.Snapshot(); err != nil {
			t.Fatal(err)
		}
		if len(mc.SeenPIDs()) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := os.RemoveAll(pidDir); err != nil {
		t.Fatal(err)
	}
	if _, err := mc.Snapshot(); err != nil {
		t.Fatal(err)
	}

	d := &Detector{Collector: mc, ProcRoot: procRoot, Grace: time.Second}
	findings, err := d.DetectHiddenProcesses()
	if err != nil {
		t.Fatalf("DetectHiddenProcesses error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected exited tree node to be ignored, got %d findings", len(findings))
	}
}

func TestDetectHiddenModules(t *testing.T) {
	sysRoot := t.TempDir()
	procRoot := t.TempDir()

	// /sys/module has evil_rootkit (with runtime state indicating it was loaded)
	mustMkdir(t, filepath.Join(sysRoot, "module", "evil_rootkit"))
	mustWrite(t, filepath.Join(sysRoot, "module", "evil_rootkit", "refcnt"), "1\n")
	// /proc/modules has only legit
	mustWrite(t, filepath.Join(procRoot, "modules"), "legit 16384 0 - Live 0x0000000000000000\n")

	d := &Detector{
		ProcRoot: procRoot,
		SysRoot:  sysRoot,
		Grace:    time.Second,
	}
	findings, err := d.DetectHiddenModules()
	if err != nil {
		t.Fatalf("DetectHiddenModules error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 hidden module finding, got %d", len(findings))
	}
	if findings[0].Type != "hidden_module" {
		t.Fatalf("expected type hidden_module, got %q", findings[0].Type)
	}
	if findings[0].Object["module"] != "evil_rootkit" {
		t.Fatalf("expected module evil_rootkit, got %v", findings[0].Object["module"])
	}
}

func TestDetectHiddenModulesIgnoresBuiltin(t *testing.T) {
	sysRoot := t.TempDir()
	procRoot := t.TempDir()

	// kernel pseudo-module exists in sysfs but not /proc/modules
	mustMkdir(t, filepath.Join(sysRoot, "module", "kernel"))
	mustWrite(t, filepath.Join(procRoot, "modules"), "\n")

	d := &Detector{ProcRoot: procRoot, SysRoot: sysRoot, Grace: time.Second}
	findings, err := d.DetectHiddenModules()
	if err != nil {
		t.Fatalf("DetectHiddenModules error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for builtin pseudo-module, got %d", len(findings))
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}
