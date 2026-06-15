package procutil

import (
	"os"
	"testing"
)

func TestUserFromPID(t *testing.T) {
	u := UserFromPID(os.Getpid())
	if u == "" {
		t.Fatal("expected non-empty user for current process")
	}
}

func TestUserFromPIDInvalid(t *testing.T) {
	u := UserFromPID(-1)
	if u != "" {
		t.Fatalf("expected empty user for invalid pid, got %q", u)
	}
}

func TestStartTicksFromStat(t *testing.T) {
	if s := StartTicksFromStat(""); s != "" {
		t.Fatalf("expected empty string, got %q", s)
	}
	if s := StartTicksFromStat("1234 (bash)"); s != "" {
		t.Fatalf("expected empty string for truncated stat, got %q", s)
	}
}
