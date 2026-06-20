package liveness

import (
	"os"
	"testing"
	"time"
)

func TestHeartbeatWriteReadAndState(t *testing.T) {
	dir := t.TempDir()
	hb := Heartbeat{
		InstanceID:        "edr-a",
		BootID:            "boot-1",
		PID:               123,
		StartTime:         time.Now().UTC(),
		Seq:               7,
		State:             "healthy",
		RestartGeneration: 2,
	}
	if err := Write(dir, hb); err != nil {
		t.Fatal(err)
	}
	got, err := Read(dir, "edr-a")
	if err != nil {
		t.Fatal(err)
	}
	if got.InstanceID != "edr-a" || got.Seq != 7 {
		t.Fatalf("unexpected heartbeat: %+v", got)
	}
	if state := State(got.UpdatedAt.Add(2*time.Second), got, 3, 5, time.Second); state != "healthy" {
		t.Fatalf("expected healthy, got %s", state)
	}
	if state := State(got.UpdatedAt.Add(4*time.Second), got, 3, 5, time.Second); state != "suspect" {
		t.Fatalf("expected suspect, got %s", state)
	}
	if state := State(got.UpdatedAt.Add(6*time.Second), got, 3, 5, time.Second); state != "down" {
		t.Fatalf("expected down, got %s", state)
	}
	if _, err := os.Stat(Path(dir, "edr-a")); err != nil {
		t.Fatal(err)
	}
}
