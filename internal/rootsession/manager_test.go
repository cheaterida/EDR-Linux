package rootsession

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"edr/internal/eventlog"
)

func TestScanTransitionsObservedToGraceToExpired(t *testing.T) {
	now := time.Date(2026, 6, 18, 9, 0, 0, 0, time.UTC)
	mgr := NewManager(Config{
		Mode:         ModeAudit,
		Secret:       []byte("secret"),
		ChallengeTTL: 10 * time.Second,
		GracePeriod:  20 * time.Second,
	}, nil)
	mgr.now = func() time.Time { return now }
	mgr.listProc = func() ([]Process, error) {
		return []Process{{
			PID:        101,
			PPID:       1,
			EUID:       0,
			Name:       "bash",
			Path:       "/usr/bin/bash",
			TTY:        "/dev/pts/0",
			StartTicks: "11",
		}}, nil
	}
	if err := mgr.Scan(); err != nil {
		t.Fatal(err)
	}
	snap := mgr.Snapshot()
	if len(snap.Sessions) != 1 {
		t.Fatalf("expected 1 session, got %#v", snap)
	}
	if snap.Sessions[0].Class != ClassAdmin || snap.Sessions[0].State != StateChallenged {
		t.Fatalf("unexpected first state: %+v", snap.Sessions[0])
	}

	now = now.Add(11 * time.Second)
	if err := mgr.Scan(); err != nil {
		t.Fatal(err)
	}
	if got := mgr.Snapshot().Sessions[0].State; got != StateGrace {
		t.Fatalf("state after challenge timeout = %q, want grace", got)
	}

	now = now.Add(21 * time.Second)
	if err := mgr.Scan(); err != nil {
		t.Fatal(err)
	}
	if got := mgr.Snapshot().Sessions[0].State; got != StateExpired {
		t.Fatalf("state after grace = %q, want expired", got)
	}
}

func TestValidateAcceptsFreshChallengeAndRejectsReplay(t *testing.T) {
	now := time.Date(2026, 6, 18, 9, 30, 0, 0, time.UTC)
	mgr := NewManager(Config{
		Mode:         ModeAudit,
		Secret:       []byte("secret"),
		ChallengeTTL: 30 * time.Second,
		GracePeriod:  10 * time.Second,
	}, nil)
	mgr.now = func() time.Time { return now }
	mgr.listProc = func() ([]Process, error) {
		return []Process{{
			PID:        202,
			PPID:       1,
			EUID:       0,
			Name:       "bash",
			Path:       "/usr/bin/bash",
			TTY:        "/dev/pts/1",
			StartTicks: "22",
		}}, nil
	}
	if err := mgr.Scan(); err != nil {
		t.Fatal(err)
	}
	ch, err := mgr.IssueChallenge(202)
	if err != nil {
		t.Fatal(err)
	}
	resp := Response{
		PID:       202,
		SessionID: ch.SessionID,
		TTY:       ch.TTY,
		Nonce:     ch.Nonce,
		Deadline:  ch.Deadline,
		Response:  ComputeResponse([]byte("secret"), ch.SessionID, ch.TTY, ch.PID, ch.Deadline, ch.Nonce),
	}
	got, err := mgr.Validate(resp)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StateValid {
		t.Fatalf("validated state = %q, want valid", got.State)
	}
	if _, err := mgr.Validate(resp); err == nil || !strings.Contains(err.Error(), "not waiting") {
		t.Fatalf("expected replay rejection, got %v", err)
	}
}

func TestScanEnforcesToolingAndBypassSkipsKill(t *testing.T) {
	now := time.Date(2026, 6, 18, 10, 0, 0, 0, time.UTC)
	var killed []int
	mgr := NewManager(Config{
		Mode:         ModeEnforceTooling,
		Secret:       []byte("secret"),
		BypassToken:  "break-glass",
		ChallengeTTL: 5 * time.Second,
		GracePeriod:  5 * time.Second,
	}, nil)
	mgr.now = func() time.Time { return now }
	mgr.killProc = func(pid int) error {
		killed = append(killed, pid)
		return nil
	}
	mgr.listProc = func() ([]Process, error) {
		return []Process{{
			PID:        303,
			PPID:       1,
			EUID:       0,
			Name:       "python3",
			Path:       "/usr/bin/python3",
			TTY:        "/dev/pts/9",
			StartTicks: "33",
		}}, nil
	}
	if err := mgr.Scan(); err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Second)
	if err := mgr.Scan(); err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Second)
	if err := mgr.Scan(); err != nil {
		t.Fatal(err)
	}
	if len(killed) != 1 || killed[0] != 303 {
		t.Fatalf("unexpected kills: %#v", killed)
	}

	killed = nil
	now = now.Add(time.Second)
	if _, err := mgr.ActivateBypass("break-glass", 30*time.Second); err != nil {
		t.Fatal(err)
	}
	mgr.sessions = map[string]*sessionState{}
	if err := mgr.Scan(); err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Second)
	if err := mgr.Scan(); err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Second)
	if err := mgr.Scan(); err != nil {
		t.Fatal(err)
	}
	if len(killed) != 0 {
		t.Fatalf("bypass should suppress kill, got %#v", killed)
	}
}

func TestScanTreatsNonTTYToolingAsUnknownRoot(t *testing.T) {
	now := time.Date(2026, 6, 18, 10, 15, 0, 0, time.UTC)
	mgr := NewManager(Config{
		Mode:         ModeAudit,
		Secret:       []byte("secret"),
		ChallengeTTL: 5 * time.Second,
		GracePeriod:  5 * time.Second,
	}, nil)
	mgr.now = func() time.Time { return now }
	mgr.listProc = func() ([]Process, error) {
		return []Process{{
			PID:        505,
			PPID:       1,
			EUID:       0,
			Name:       "python3",
			Path:       "/usr/bin/python3",
			StartTicks: "55",
		}}, nil
	}
	if err := mgr.Scan(); err != nil {
		t.Fatal(err)
	}
	snap := mgr.Snapshot()
	if len(snap.Sessions) != 1 {
		t.Fatalf("expected non-tty tooling to be tracked, got %+v", snap.Sessions)
	}
	if snap.Sessions[0].Class != ClassUnknown || snap.Sessions[0].State != StateChallenged {
		t.Fatalf("unexpected non-tty tooling state: %+v", snap.Sessions[0])
	}
}

func TestScanSkipsTrustedNonTTYService(t *testing.T) {
	now := time.Date(2026, 6, 18, 10, 16, 0, 0, time.UTC)
	mgr := NewManager(Config{
		Mode:         ModeAudit,
		Secret:       []byte("secret"),
		ChallengeTTL: 5 * time.Second,
		GracePeriod:  5 * time.Second,
	}, nil)
	mgr.now = func() time.Time { return now }
	mgr.listProc = func() ([]Process, error) {
		return []Process{{
			PID:         606,
			PPID:        1,
			EUID:        0,
			Name:        "nginx",
			Path:        "/usr/sbin/nginx",
			Cgroup:      "0::/system.slice/nginx.service",
			ServiceUnit: "nginx.service",
			StartTicks:  "66",
		}}, nil
	}
	if err := mgr.Scan(); err != nil {
		t.Fatal(err)
	}
	snap := mgr.Snapshot()
	if len(snap.Sessions) != 0 {
		t.Fatalf("expected trusted service to be skipped, got %+v", snap.Sessions)
	}
}

func TestScanSkipsKernelThreadLikeRootProcess(t *testing.T) {
	now := time.Date(2026, 6, 18, 10, 17, 0, 0, time.UTC)
	mgr := NewManager(Config{
		Mode:         ModeAudit,
		Secret:       []byte("secret"),
		ChallengeTTL: 5 * time.Second,
		GracePeriod:  5 * time.Second,
	}, nil)
	mgr.now = func() time.Time { return now }
	mgr.listProc = func() ([]Process, error) {
		return []Process{{
			PID:        2,
			PPID:       0,
			EUID:       0,
			Name:       "kthreadd",
			Cgroup:     "0::/\n",
			StartTicks: "2",
		}}, nil
	}
	if err := mgr.Scan(); err != nil {
		t.Fatal(err)
	}
	if got := mgr.Snapshot().Sessions; len(got) != 0 {
		t.Fatalf("expected kernel thread to be skipped, got %+v", got)
	}
}

func TestScanSkipsInitScopeRootProcess(t *testing.T) {
	now := time.Date(2026, 6, 18, 10, 18, 0, 0, time.UTC)
	mgr := NewManager(Config{
		Mode:         ModeAudit,
		Secret:       []byte("secret"),
		ChallengeTTL: 5 * time.Second,
		GracePeriod:  5 * time.Second,
	}, nil)
	mgr.now = func() time.Time { return now }
	mgr.listProc = func() ([]Process, error) {
		return []Process{{
			PID:         1,
			PPID:        0,
			EUID:        0,
			Name:        "systemd",
			Path:        "/usr/lib/systemd/systemd",
			Cgroup:      "0::/init.scope\n",
			ServiceUnit: "init.scope",
			StartTicks:  "1",
		}}, nil
	}
	if err := mgr.Scan(); err != nil {
		t.Fatal(err)
	}
	if got := mgr.Snapshot().Sessions; len(got) != 0 {
		t.Fatalf("expected init scope process to be skipped, got %+v", got)
	}
}

func TestScanWritesAuditEvents(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.jsonl")
	logger, err := eventlog.NewWithOptions(logPath, eventlog.Options{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 18, 10, 30, 0, 0, time.UTC)
	mgr := NewManager(Config{
		Mode:         ModeAudit,
		Secret:       []byte("secret"),
		ChallengeTTL: 5 * time.Second,
		GracePeriod:  5 * time.Second,
	}, logger)
	mgr.now = func() time.Time { return now }
	mgr.listProc = func() ([]Process, error) {
		return []Process{{
			PID:        404,
			PPID:       1,
			EUID:       0,
			Name:       "bash",
			Path:       "/usr/bin/bash",
			TTY:        "/dev/pts/2",
			StartTicks: "44",
		}}, nil
	}
	if err := mgr.Scan(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected observed+challenged events, got %s", string(raw))
	}
	var ev eventlog.Event
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Category != "root_session" || ev.Action != "root_session_challenged" {
		t.Fatalf("unexpected audit event: %+v", ev)
	}
}

func TestBypassPersistsAcrossManagerRestartAndCanBeCleared(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "root-session-state.json")
	now := time.Now().UTC().Add(2 * time.Minute).Truncate(time.Second)

	mgr := NewManager(Config{
		Mode:        ModeAudit,
		StatePath:   statePath,
		BypassToken: "break-glass",
		BypassTTL:   5 * time.Minute,
	}, nil)
	mgr.now = func() time.Time { return now }
	until, err := mgr.ActivateBypass("break-glass", 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if until.IsZero() {
		t.Fatal("expected non-zero bypass expiry")
	}

	reloaded := NewManager(Config{
		Mode:      ModeAudit,
		StatePath: statePath,
	}, nil)
	reloaded.now = func() time.Time { return now }
	snap := reloaded.Snapshot()
	if !snap.BypassUntil.Equal(until) {
		t.Fatalf("reloaded bypass_until = %v, want %v", snap.BypassUntil, until)
	}

	if err := reloaded.RevokeBypass(); err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Snapshot().BypassUntil; !got.IsZero() {
		t.Fatalf("bypass should be cleared, got %v", got)
	}

	reloadedAgain := NewManager(Config{
		Mode:      ModeAudit,
		StatePath: statePath,
	}, nil)
	reloadedAgain.now = func() time.Time { return now }
	if got := reloadedAgain.Snapshot().BypassUntil; !got.IsZero() {
		t.Fatalf("persisted bypass should be cleared, got %v", got)
	}
}
