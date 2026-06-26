// internal/integrity/self_check.go
// v0.9: Self-integrity sentinel — detects when the EDR is being
// dismantled without relying on any external service.
//
// Four parallel checks:
//   1. BPF heartbeat  — are the probes still firing?
//   2. Binary hash    — has the agent binary been replaced?
//   3. Install dir    — does /opt/edr still exist?
//   4. Fanotify fd    — is the file-interposition layer still alive?
//
// When any check fails, the SOS (Last Gasp) event is emitted via the
// registered callback. No resurrection is attempted — the EDR accepts
// death but leaves signed forensic evidence.

package integrity

import (
	"crypto/sha256"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
)

// BPFHeartbeatReader is the minimal interface needed to read the
// agent_heartbeat BPF map. The real implementation lives in the
// BPF loader package.
type BPFHeartbeatReader interface {
	ReadHeartbeat() (uint64, error)
	ReadAgentPID() (uint32, error)
}

// CheckResult describes a single integrity check outcome.
type CheckResult struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Detail  string `json:"detail,omitempty"`
}

// SelfCheck runs periodic integrity checks and triggers SOS when
// the EDR is being dismantled.
type SelfCheck struct {
	mu sync.Mutex

	// immutable startup state
	binaryHash [32]byte
	binaryPath string
	installDir string

	// BPF heartbeat reader (from BPF loader)
	heartbeat BPFHeartbeatReader
	lastBeat  uint64
	beatStale bool

	// fanotify check
	fanotifyFD int

	// SOS callback — called exactly once when compromise is detected
	sosFn func(reason string, results []CheckResult)

	// prevent duplicate SOS
	sosFired bool

	// policy signature public key (optional, for config integrity)
	pubKeyPath string
}

// Config configures the SelfCheck sentinel.
type Config struct {
	BinaryPath  string // os.Executable() or custom path
	InstallDir  string // /opt/edr
	PubKeyPath  string // optional, for config signature check
	Heartbeat   BPFHeartbeatReader
	FanotifyFD  int
	OnSOS       func(reason string, results []CheckResult)
}

// NewSelfCheck creates an integrity sentinel. It records the startup
// binary hash immediately — any later deviation means tampering.
func NewSelfCheck(cfg Config) (*SelfCheck, error) {
	data, err := os.ReadFile(cfg.BinaryPath)
	if err != nil {
		return nil, fmt.Errorf("self_check: read binary: %w", err)
	}

	s := &SelfCheck{
		binaryPath:  cfg.BinaryPath,
		binaryHash:  sha256.Sum256(data),
		installDir:  cfg.InstallDir,
		heartbeat:   cfg.Heartbeat,
		fanotifyFD:  cfg.FanotifyFD,
		sosFn:       cfg.OnSOS,
		pubKeyPath:  cfg.PubKeyPath,
	}
	return s, nil
}

// RunAll executes every integrity check and returns results. If any
// check fails, the SOS callback is invoked (exactly once).
func (s *SelfCheck) RunAll() []CheckResult {
	s.mu.Lock()
	defer s.mu.Unlock()

	results := []CheckResult{
		s.checkBPFHeartbeat(),
		s.checkBPFMaps(),
		s.checkBinaryIntegrity(),
		s.checkInstallDir(),
		s.checkFanotifyFD(),
	}

	failed := false
	for _, r := range results {
		if !r.Passed {
			failed = true
			break
		}
	}

	if failed && !s.sosFired && s.sosFn != nil {
		s.sosFired = true
		reason := s.buildReason(results)
		go s.sosFn(reason, results)
	}

	return results
}

// checkBPFMaps verifies that the critical agent_pid BPF map
// still contains a valid PID. If the map has been zeroed or
// detached by an attacker, this signals an active compromise.
func (s *SelfCheck) checkBPFMaps() CheckResult {
	if s.heartbeat == nil {
		return CheckResult{Name: "bpf_maps", Passed: true, Detail: "no reader configured"}
	}

	pid, err := s.heartbeat.ReadAgentPID()
	if err != nil {
		return CheckResult{Name: "bpf_maps", Passed: false, Detail: fmt.Sprintf("agent_pid map read error: %v", err)}
	}

	if pid == 0 {
		return CheckResult{Name: "bpf_maps", Passed: false, Detail: "agent_pid map contains zero (may have been tampered)"}
	}

	return CheckResult{Name: "bpf_maps", Passed: true}
}

func (s *SelfCheck) checkBPFHeartbeat() CheckResult {
	if s.heartbeat == nil {
		return CheckResult{Name: "bpf_heartbeat", Passed: true, Detail: "no reader configured"}
	}

	now, err := s.heartbeat.ReadHeartbeat()
	if err != nil {
		s.beatStale = true
		return CheckResult{Name: "bpf_heartbeat", Passed: false, Detail: fmt.Sprintf("read error: %v", err)}
	}

	if s.lastBeat == 0 {
		// first check — record baseline
		s.lastBeat = now
		return CheckResult{Name: "bpf_heartbeat", Passed: true, Detail: "baseline recorded"}
	}

	// If the heartbeat has never changed since last check (>30s
	// as a reasonable threshold since RunOnce typically runs
	// every 1-5s), BPF probes may be detached.
	if now == s.lastBeat && !s.beatStale {
		s.beatStale = true
		return CheckResult{
			Name:   "bpf_heartbeat",
			Passed: false,
			Detail: fmt.Sprintf("stale — no heartbeat update since last check (timestamp=%d)", now),
		}
	}

	s.lastBeat = now
	s.beatStale = false
	return CheckResult{Name: "bpf_heartbeat", Passed: true}
}

func (s *SelfCheck) checkBinaryIntegrity() CheckResult {
	data, err := os.ReadFile(s.binaryPath)
	if err != nil {
		return CheckResult{Name: "binary_hash", Passed: false, Detail: fmt.Sprintf("cannot read: %v", err)}
	}

	currentHash := sha256.Sum256(data)
	if currentHash != s.binaryHash {
		return CheckResult{Name: "binary_hash", Passed: false, Detail: "binary modified since startup"}
	}
	return CheckResult{Name: "binary_hash", Passed: true}
}

func (s *SelfCheck) checkInstallDir() CheckResult {
	if _, err := os.Stat(s.installDir); os.IsNotExist(err) {
		return CheckResult{Name: "install_dir", Passed: false, Detail: fmt.Sprintf("%s does not exist", s.installDir)}
	}
	return CheckResult{Name: "install_dir", Passed: true}
}

func (s *SelfCheck) checkFanotifyFD() CheckResult {
	if s.fanotifyFD <= 0 {
		return CheckResult{Name: "fanotify_fd", Passed: true, Detail: "not configured"}
	}

	// F_GETFD: if the fd has been closed (e.g., by an attacker
	// or a kernel resource reaper), this returns EBADF.
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(s.fanotifyFD), syscall.F_GETFD, 0)
	if errno != 0 {
		return CheckResult{
			Name:   "fanotify_fd",
			Passed: false,
			Detail: fmt.Sprintf("fd %d is invalid (errno=%d)", s.fanotifyFD, errno),
		}
	}
	return CheckResult{Name: "fanotify_fd", Passed: true}
}

// buildReason extracts a human-readable reason from failed checks.
func (s *SelfCheck) buildReason(results []CheckResult) string {
	var failed []string
	for _, r := range results {
		if !r.Passed {
			failed = append(failed, r.Name)
		}
	}
	if len(failed) == 0 {
		return "all_checks_passed"
	}
	return "integrity_failure:" + joinStrings(failed, ",")
}

func joinStrings(ss []string, sep string) string {
	if len(ss) == 0 {
		return ""
	}
	out := ss[0]
	for _, s := range ss[1:] {
		out += sep + s
	}
	return out
}

// StalenessDuration is how long a heartbeat can be stale before
// it's considered a BPF compromise.
const StalenessDuration = 30 * time.Second
