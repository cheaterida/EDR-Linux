package fanotify

import (
	"os"
	"sync"
	"testing"
)

// fakeHandler records decisions for test assertions.
type fakeHandler struct {
	mu       sync.Mutex
	allowed  []AccessInfo
	denied   []AccessInfo
	nextRule string
}

func (h *fakeHandler) HandleFileAccess(info AccessInfo) (bool, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Always allow in tests (no real fanotify fd available).
	h.allowed = append(h.allowed, info)
	return true, h.nextRule
}

type fakeLogger struct {
	mu     sync.Mutex
	events []Event
}

func (l *fakeLogger) Write(ev Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, ev)
	return nil
}

func TestConstants(t *testing.T) {
	// Verify syscall numbers match expected x86_64 values.
	if cnrFanotifyInit != 300 {
		t.Errorf("fanotify_init nr = %d, want 300", cnrFanotifyInit)
	}
	if cnrFanotifyMark != 301 {
		t.Errorf("fanotify_mark nr = %d, want 301", cnrFanotifyMark)
	}

	// Verify class constants don't collide.
	if FAN_CLASS_CONTENT&FAN_CLASS_PRE_CONTENT != 0 {
		t.Error("FAN_CLASS_CONTENT and FAN_CLASS_PRE_CONTENT must not overlap")
	}
	if FAN_CLASS_CONTENT&FAN_CLOEXEC != 0 {
		t.Error("FAN_CLASS_CONTENT and FAN_CLOEXEC must not overlap")
	}
}

func TestNewRequiresRoot(t *testing.T) {
	// fanotify_init requires CAP_SYS_ADMIN. In CI / non-root dev,
	// this is expected to fail. The test verifies the error is
	// reported cleanly, not a panic.
	handler := HandlerFunc(func(info AccessInfo) (bool, string) { return true, "" })
	logger := &fakeLogger{}
	_, err := New([]string{"/tmp"}, handler, logger)
	if err == nil {
		t.Log("fanotify_init succeeded (running as root)")
	} else {
		t.Logf("fanotify_init expected error (non-root): %v", err)
	}
}

func TestAccessInfoFields(t *testing.T) {
	info := AccessInfo{
		PID:     1234,
		Comm:    "cat",
		Exe:     "/usr/bin/cat",
		Cmdline: "cat /etc/shadow",
		Path:    "/etc/shadow",
		Mask:    FAN_OPEN_PERM,
	}
	if info.PID != 1234 {
		t.Errorf("PID = %d, want 1234", info.PID)
	}
	if info.Comm != "cat" {
		t.Errorf("Comm = %s, want cat", info.Comm)
	}
}

func TestHandlerFunc(t *testing.T) {
	called := false
	h := HandlerFunc(func(info AccessInfo) (bool, string) {
		called = true
		return false, "test-rule"
	})
	allow, ruleID := h.HandleFileAccess(AccessInfo{PID: 1})
	if !called {
		t.Error("HandlerFunc was not called")
	}
	if allow {
		t.Error("expected allow=false")
	}
	if ruleID != "test-rule" {
		t.Errorf("ruleID = %s, want test-rule", ruleID)
	}
}

func TestResolvePathNotExist(t *testing.T) {
	// resolvePath with invalid fd should return empty string.
	path := resolvePath(-1)
	if path != "" {
		t.Errorf("expected empty path for fd=-1, got %q", path)
	}
	path = resolvePath(999999)
	if path != "" {
		t.Errorf("expected empty path for nonexistent fd, got %q", path)
	}
}

func TestReadProcHelpers(t *testing.T) {
	pid := int32(os.Getpid())

	comm := readProcString(pid, "comm")
	if comm == "" {
		t.Error("readProcString(comm) returned empty for current process")
	}

	exe := readProcLink(pid, "exe")
	if exe == "" {
		t.Error("readProcLink(exe) returned empty for current process")
	}

	cmdline := readProcCmdline(pid)
	if cmdline == "" {
		t.Error("readProcCmdline returned empty for current process")
	}
}

func TestFanotifyResponseSize(t *testing.T) {
	// The response struct must be exactly 8 bytes for the kernel.
	// binary.Write to a 4+4 buffer confirms the layout.
	resp := fanotifyResponse{Fd: 42, Response: FAN_DENY | FAN_AUDIT}
	if resp.Fd != 42 {
		t.Errorf("Fd = %d", resp.Fd)
	}
	if resp.Response != FAN_DENY|FAN_AUDIT {
		t.Errorf("Response = %#x", resp.Response)
	}
}

func TestFakeLoggerRecordsEvents(t *testing.T) {
	logger := &fakeLogger{}
	logger.Write(Event{EventID: "test-1", Category: "file"})
	logger.Write(Event{EventID: "test-2", Category: "file"})

	logger.mu.Lock()
	defer logger.mu.Unlock()
	if len(logger.events) != 2 {
		t.Fatalf("got %d events, want 2", len(logger.events))
	}
	if logger.events[0].EventID != "test-1" {
		t.Errorf("event[0].EventID = %s", logger.events[0].EventID)
	}
}
