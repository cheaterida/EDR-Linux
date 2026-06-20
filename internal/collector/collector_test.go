package collector

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProcessUserField(t *testing.T) {
	collector := &ProcfsCollector{}
	snap, err := collector.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	self := os.Getpid()
	for _, p := range snap.Processes {
		if p.PID == self {
			if p.User == "" {
				t.Fatal("expected non-empty User for current process")
			}
			return
		}
	}
	t.Fatal("current process not found in snapshot")
}

func TestProcfsCollectorFileWatchPoll(t *testing.T) {
	dir := t.TempDir()
	collector := &ProcfsCollector{WatchPaths: []string{dir}, WatchMode: "poll"}
	if _, err := collector.Snapshot(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	snap, err := collector.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.FileEvents) == 0 || snap.FileEvents[0].Op != "create" {
		t.Fatalf("expected create file event, got %#v", snap.FileEvents)
	}
}

func TestProcfsCollectorFileWatchInotify(t *testing.T) {
	dir := t.TempDir()
	collector := &ProcfsCollector{WatchPaths: []string{dir}, WatchMode: "inotify"}
	if _, err := collector.Snapshot(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snap, err := collector.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range snap.FileEvents {
			if event.Path == path && (event.Op == "create" || event.Op == "write") {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("expected inotify event for %s", path)
}
