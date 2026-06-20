package control

import (
	"path/filepath"
	"testing"
	"time"
)

func TestCooldownBlocksThenExpires(t *testing.T) {
	s := NewSuppressor(SuppressorOptions{ProcessCooldown: 50 * time.Millisecond, RatePerSec: 0, Burst: 1})
	if ok, _ := s.Allow("process", "r1", "process:r1:1:ticks"); !ok {
		t.Fatal("first call should be allowed")
	}
	if ok, reason := s.Allow("process", "r1", "process:r1:1:ticks"); ok || reason != ReasonCooldown {
		t.Fatalf("second call should be blocked by cooldown, got ok=%v reason=%q", ok, reason)
	}
	time.Sleep(60 * time.Millisecond)
	if ok, _ := s.Allow("process", "r1", "process:r1:1:ticks"); !ok {
		t.Fatal("after cooldown the call should be allowed")
	}
}

func TestRateLimitIsPerRule(t *testing.T) {
	s := NewSuppressor(SuppressorOptions{ProcessCooldown: 0, RatePerSec: 2, Burst: 2})
	for i := 0; i < 2; i++ {
		if ok, reason := s.Allow("process", "r1", "process:r1:k"+itoa(i)); !ok {
			t.Fatalf("expected first two emits to pass, got %d blocked reason=%q", i, reason)
		}
	}
	if ok, reason := s.Allow("process", "r1", "process:r1:k3"); ok || reason != ReasonRateLimit {
		t.Fatalf("third emit in same second should be rate-limited, got ok=%v reason=%q", ok, reason)
	}
	if ok, _ := s.Allow("process", "r2", "process:r2:k1"); !ok {
		t.Fatal("rate limit is per-rule, r2 should still pass")
	}
}

func TestFileCooldownDifferentFromProcess(t *testing.T) {
	s := NewSuppressor(SuppressorOptions{ProcessCooldown: time.Second, FileCooldown: 0, RatePerSec: 0, Burst: 1})
	if ok, _ := s.Allow("process", "r1", "process:r1:1"); !ok {
		t.Fatal("first process call should pass")
	}
	if ok, _ := s.Allow("process", "r1", "process:r1:1"); ok {
		t.Fatal("second process call should be blocked")
	}
	if ok, _ := s.Allow("file", "r1", "file:r1:/tmp/x:write"); !ok {
		t.Fatal("file category with 0 cooldown should pass independently")
	}
}

func TestNilSuppressorAllows(t *testing.T) {
	var s *Suppressor
	if ok, reason := s.Allow("process", "r1", "k"); !ok || reason != "" {
		t.Fatalf("nil suppressor should allow, got ok=%v reason=%q", ok, reason)
	}
}

func TestDedupKeySkipsEmptyParts(t *testing.T) {
	if got, want := DedupKey("process", "r1", "1", "", "ticks"), "process:r1:1:ticks"; got != want {
		t.Fatalf("dedup key = %q, want %q", got, want)
	}
}

func TestStatsAccurate(t *testing.T) {
	s := NewSuppressor(SuppressorOptions{ProcessCooldown: 0, RatePerSec: 10, Burst: 5})
	for i, k := range []string{"process:r1:1", "process:r1:2", "process:r2:1", "process:r2:2", "process:r3:1"} {
		if ok, _ := s.Allow("process", []string{"r1", "r1", "r2", "r2", "r3"}[i], k); !ok {
			t.Fatalf("call %d should pass, got blocked", i)
		}
	}
	tracked, rules := s.Stats()
	if tracked != 5 || rules != 3 {
		t.Fatalf("stats = (tracked=%d, rules=%d), want (5, 3)", tracked, rules)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func TestSuppressorSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "suppress.json")

	// Create a suppressor and exercise it.
	s1 := NewSuppressor(SuppressorOptions{ProcessCooldown: 10 * time.Second, RatePerSec: 5, Burst: 5})
	// Use up 3 tokens.
	for i := 0; i < 3; i++ {
		if ok, _ := s1.Allow("process", "r1", "process:r1:k"+itoa(i)); !ok {
			t.Fatalf("unexpected block at i=%d", i)
		}
	}
	// Add a cooldown entry.
	s1.Allow("file", "f1", "file:f1:/tmp/x:write")

	if err := s1.SaveState(statePath); err != nil {
		t.Fatal(err)
	}

	// Load into a fresh suppressor.
	s2 := NewSuppressor(SuppressorOptions{ProcessCooldown: 10 * time.Second, RatePerSec: 5, Burst: 5})
	if err := s2.LoadState(statePath); err != nil {
		t.Fatal(err)
	}

	// Verify: the cooldown entry should block.
	ok, reason := s2.Allow("file", "f1", "file:f1:/tmp/x:write")
	if ok || reason != ReasonCooldown {
		t.Fatalf("expected cooldown after load, got ok=%v reason=%q", ok, reason)
	}

	// Verify: rate limit state was restored (2 tokens remain out of 5).
	// Third new key should pass (token 4), fourth should pass (token 5),
	// fifth should be rate-limited.
	for i := 0; i < 2; i++ {
		if ok, _ := s2.Allow("process", "r1", "process:r1:newk"+itoa(i)); !ok {
			t.Fatalf("expected pass for new key %d after token restore", i)
		}
	}
	if ok, reason := s2.Allow("process", "r1", "process:r1:newk3"); ok || reason != ReasonRateLimit {
		t.Fatalf("expected rate limit after restored token exhaustion, got ok=%v reason=%q", ok, reason)
	}

	// Stats should reflect loaded state.
	tracked, rules := s2.Stats()
	if tracked < 4 {
		t.Fatalf("stats tracked=%d, want >= 4", tracked)
	}
	if rules < 2 {
		t.Fatalf("stats rules=%d, want >= 2", rules)
	}
}

func TestSuppressorLoadMissingFile(t *testing.T) {
	s := NewSuppressor(SuppressorOptions{ProcessCooldown: time.Minute, RatePerSec: 0})
	if err := s.LoadState("/nonexistent/path/suppress.json"); err != nil {
		t.Fatalf("LoadState should silently ignore missing file: %v", err)
	}
}

func TestSuppressorSaveNilIsNoop(t *testing.T) {
	var s *Suppressor
	if err := s.SaveState("/tmp/ignored.json"); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadState("/tmp/ignored.json"); err != nil {
		t.Fatal(err)
	}
}

func TestSuppressorSnapshot(t *testing.T) {
	s := NewSuppressor(SuppressorOptions{RatePerSec: 0})
	s.Allow("process", "r1", "process:r1:k1")
	s.Allow("process", "r1", "process:r1:k2")

	snap := s.Snapshot()
	if snap["active"] != true {
		t.Fatal("expected active=true")
	}
	if snap["tracked_events"].(int) < 1 {
		t.Fatalf("expected tracked_events >= 1, got %v", snap["tracked_events"])
	}

	var nilSnap *Suppressor
	ns := nilSnap.Snapshot()
	if ns["active"] != false {
		t.Fatal("nil suppressor should report inactive")
	}
}
