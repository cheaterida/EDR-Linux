package lease

import (
	"testing"
	"time"
)

func TestAcquireAndReleaseLease(t *testing.T) {
	dir := t.TempDir()
	first := Lease{
		LeaseID:    "l1",
		Target:     "edr-b",
		RequestID:  "r1",
		Source:     "edr-a",
		Generation: 1,
		Priority:   100,
		AcquiredAt: time.Now().UTC(),
		ExpiresAt:  time.Now().UTC().Add(10 * time.Second),
	}
	got, ok, err := Acquire(dir, first)
	if err != nil || !ok {
		t.Fatalf("acquire first lease failed: ok=%v err=%v", ok, err)
	}
	if got.LeaseID != "l1" {
		t.Fatalf("unexpected lease: %+v", got)
	}

	second := Lease{
		LeaseID:    "l2",
		Target:     "edr-b",
		RequestID:  "r2",
		Source:     "edr-c",
		Generation: 2,
		Priority:   50,
		AcquiredAt: time.Now().UTC(),
		ExpiresAt:  time.Now().UTC().Add(10 * time.Second),
	}
	if _, ok, err := Acquire(dir, second); err != nil || ok {
		t.Fatalf("lower-priority lease should not win: ok=%v err=%v", ok, err)
	}
	if err := Release(dir, "edr-b", "l1"); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir, "edr-b"); err == nil {
		t.Fatal("expected released lease to be gone")
	}
}
