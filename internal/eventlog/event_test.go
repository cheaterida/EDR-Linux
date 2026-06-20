package eventlog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHostnameCached(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	logger, err := NewWithOptions(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if logger.host == "" {
		t.Fatal("hostname should be cached at init")
	}
	if err := logger.Write(Event{EventID: "e1", Category: "process", Action: "observe", Decision: "alert"}); err != nil {
		t.Fatal(err)
	}
	evts := readEvents(t, path)
	if len(evts) != 1 {
		t.Fatalf("expected 1 event")
	}
	if evts[0].Host != logger.host {
		t.Fatalf("event host = %q, want %q", evts[0].Host, logger.host)
	}
}

func TestLoggerRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	logger, err := NewWithOptions(path, Options{MaxBytes: 64, MaxBackups: 2})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := logger.Write(Event{EventID: "evt", Category: "process", Severity: "low", Action: "observe", Decision: "alert"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("expected rotated backup, got %v", err)
	}
}
