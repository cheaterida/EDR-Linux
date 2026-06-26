package rootsession

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"edr/internal/eventlog"
	"edr/internal/procutil"
)

const (
	ModeOff            = "off"
	ModeAudit          = "audit"
	ModeEnforceAdmin   = "enforce-admin"
	ModeEnforceTooling = "enforce-tooling"

	ClassSystem  = "class-system"
	ClassAdmin   = "class-admin"
	ClassTooling = "class-tooling"
	ClassUnknown = "class-unknown-root"

	StateObserved   = "observed"
	StateChallenged = "challenged"
	StateValid      = "valid"
	StateGrace      = "grace"
	StateExpired    = "expired"
)

var errNoSecret = errors.New("root session secret is empty")

type Config struct {
	Mode         string
	Secret       []byte
	ScanEvery    time.Duration
	ChallengeTTL time.Duration
	GracePeriod  time.Duration
	StatePath    string
	BypassToken  string
	BypassTTL    time.Duration
	SystemNames  []string
	ShellNames   []string
	ToolingNames []string
}

type Process struct {
	PID         int
	PPID        int
	EUID        int
	Name        string
	Path        string
	Cmdline     string
	TTY         string
	Cgroup      string
	ServiceUnit string
	StartTicks  string
}

type Challenge struct {
	SessionID string    `json:"session_id"`
	Class     string    `json:"class"`
	PID       int       `json:"pid"`
	TTY       string    `json:"tty"`
	Nonce     string    `json:"nonce"`
	Deadline  time.Time `json:"deadline"`
	IssuedAt  time.Time `json:"issued_at"`
}

type Response struct {
	PID       int       `json:"pid"`
	SessionID string    `json:"session_id"`
	TTY       string    `json:"tty"`
	Nonce     string    `json:"nonce"`
	Deadline  time.Time `json:"deadline"`
	Response  string    `json:"response"`
}

type Session struct {
	SessionID      string    `json:"session_id"`
	Class          string    `json:"class"`
	State          string    `json:"state"`
	PID            int       `json:"pid"`
	PPID           int       `json:"ppid"`
	Name           string    `json:"name"`
	Path           string    `json:"path,omitempty"`
	Cmdline        string    `json:"cmdline,omitempty"`
	TTY            string    `json:"tty,omitempty"`
	FirstSeenAt    time.Time `json:"first_seen_at"`
	LastSeenAt     time.Time `json:"last_seen_at"`
	ChallengeAt    time.Time `json:"challenge_at,omitempty"`
	ChallengeBy    time.Time `json:"challenge_deadline,omitempty"`
	ValidatedAt    time.Time `json:"validated_at,omitempty"`
	GraceUntil     time.Time `json:"grace_until,omitempty"`
	LastAction     string    `json:"last_action,omitempty"`
	LastError      string    `json:"last_error,omitempty"`
	LastEnforcedAt time.Time `json:"last_enforced_at,omitempty"`
}

type Snapshot struct {
	Enabled     bool           `json:"enabled"`
	Mode        string         `json:"mode"`
	BypassUntil time.Time      `json:"bypass_until,omitempty"`
	Counts      map[string]int `json:"counts"`
	Sessions    []Session      `json:"sessions"`
}

type Manager struct {
	mu       sync.Mutex
	cfg      Config
	logger   *eventlog.Logger
	now      func() time.Time
	listProc func() ([]Process, error)
	killProc func(int) error
	sessions map[string]*sessionState
	bypassAt time.Time
}

type sessionState struct {
	Session
	nonce string
}

type persistedState struct {
	BypassUntil time.Time `json:"bypass_until,omitempty"`
}

func NewManager(cfg Config, logger *eventlog.Logger) *Manager {
	cfg = normalizeConfig(cfg)
	mgr := &Manager{
		cfg:      cfg,
		logger:   logger,
		now:      func() time.Time { return time.Now().UTC() },
		listProc: ListRootProcesses,
		killProc: killPID,
		sessions: make(map[string]*sessionState),
	}
	_ = mgr.loadStateLocked()
	return mgr
}

func normalizeConfig(cfg Config) Config {
	cfg.Mode = strings.TrimSpace(cfg.Mode)
	if cfg.Mode == "" {
		cfg.Mode = ModeOff
	}
	if cfg.ScanEvery <= 0 {
		cfg.ScanEvery = 5 * time.Second
	}
	if cfg.ChallengeTTL <= 0 {
		cfg.ChallengeTTL = 30 * time.Second
	}
	if cfg.GracePeriod <= 0 {
		cfg.GracePeriod = 30 * time.Second
	}
	if cfg.BypassTTL <= 0 {
		cfg.BypassTTL = 5 * time.Minute
	}
	if len(cfg.SystemNames) == 0 {
		cfg.SystemNames = []string{
			"systemd", "systemd-logind", "systemd-journald", "sshd", "cron", "crond",
			"dbus-daemon", "dbus-broker", "apt", "apt-get", "dpkg", "unattended-upgrade",
		}
	}
	if len(cfg.ShellNames) == 0 {
		cfg.ShellNames = []string{"bash", "sh", "dash", "zsh", "fish", "tmux", "screen"}
	}
	if len(cfg.ToolingNames) == 0 {
		cfg.ToolingNames = []string{
			"sudo", "su", "bash", "sh", "dash", "zsh", "python", "python3", "perl", "ruby", "busybox",
		}
	}
	return cfg
}

func (m *Manager) Enabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.Mode != ModeOff
}

func (m *Manager) ScanEvery() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.ScanEvery
}

func (m *Manager) Scan() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.scanLocked()
}

func (m *Manager) IssueChallenge(pid int) (Challenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.scanLocked(); err != nil {
		return Challenge{}, err
	}
	s, err := m.findByPIDLocked(pid)
	if err != nil {
		return Challenge{}, err
	}
	if s.Class == ClassSystem {
		return Challenge{}, fmt.Errorf("pid %d is a whitelisted system process", pid)
	}
	ch := m.issueChallengeLocked(s, m.now(), "manual")
	return ch, nil
}

func (m *Manager) Validate(resp Response) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.cfg.Secret) == 0 {
		return Session{}, errNoSecret
	}
	s, ok := m.sessions[resp.SessionID]
	if !ok || s.PID != resp.PID {
		return Session{}, fmt.Errorf("session %q not found for pid %d", resp.SessionID, resp.PID)
	}
	now := m.now()
	if s.State != StateChallenged {
		return Session{}, fmt.Errorf("session %q is not waiting for challenge response", resp.SessionID)
	}
	if resp.Nonce == "" || resp.Nonce != s.nonce {
		return Session{}, fmt.Errorf("invalid nonce for session %q", resp.SessionID)
	}
	if !resp.Deadline.Equal(s.ChallengeBy) {
		return Session{}, fmt.Errorf("invalid deadline for session %q", resp.SessionID)
	}
	if now.After(s.ChallengeBy) {
		return Session{}, fmt.Errorf("challenge for session %q has expired", resp.SessionID)
	}
	expected := ComputeResponse(m.cfg.Secret, s.SessionID, s.TTY, s.PID, s.ChallengeBy, s.nonce)
	if !hmac.Equal([]byte(resp.Response), []byte(expected)) {
		return Session{}, fmt.Errorf("invalid challenge response for session %q", resp.SessionID)
	}
	s.State = StateValid
	s.ValidatedAt = now
	s.GraceUntil = time.Time{}
	s.LastAction = "validated"
	s.LastError = ""
	s.nonce = ""
	m.auditLocked("root_session_validated", "root-session-valid", "info", "allow", s, map[string]any{
		"validated_at": now,
	})
	return s.Session, nil
}

func (m *Manager) ActivateBypass(token string, ttl time.Duration) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if strings.TrimSpace(m.cfg.BypassToken) == "" {
		return time.Time{}, errors.New("root session bypass is not configured")
	}
	if !hmac.Equal([]byte(strings.TrimSpace(token)), []byte(m.cfg.BypassToken)) {
		return time.Time{}, errors.New("invalid root session bypass token")
	}
	if ttl <= 0 {
		ttl = m.cfg.BypassTTL
	}
	until := m.now().Add(ttl)
	m.auditBypassLocked(until, ttl)
	if err := m.saveStateLocked(); err != nil {
		return time.Time{}, err
	}
	return until, nil
}

func (m *Manager) RevokeBypass() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.bypassAt.IsZero() {
		return nil
	}
	until := m.bypassAt
	m.bypassAt = time.Time{}
	if err := m.saveStateLocked(); err != nil {
		m.bypassAt = until
		return err
	}
	if m.logger != nil {
		_ = m.logger.Write(eventlog.Event{
			EventID:  fmt.Sprintf("root-session-bypass-clear-%d", m.now().UnixNano()),
			Category: "root_session",
			Severity: "high",
			Action:   "root_session_bypass_cleared",
			Decision: "allow",
			RuleID:   "root-session-bypass-clear",
			Subject:  map[string]any{"mode": m.cfg.Mode},
			Evidence: map[string]any{"previous_bypass_until": until},
		})
	}
	return nil
}

func (m *Manager) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	out := Snapshot{
		Enabled:     m.cfg.Mode != ModeOff,
		Mode:        m.cfg.Mode,
		Counts:      map[string]int{},
		BypassUntil: time.Time{},
	}
	if until := m.bypassUntilLocked(); until.After(now) {
		out.BypassUntil = until
	}
	sessions := make([]Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		copy := s.Session
		sessions = append(sessions, copy)
		out.Counts[copy.Class]++
		out.Counts[copy.State]++
	}
	sort.Slice(sessions, func(i, j int) bool {
		if sessions[i].PID != sessions[j].PID {
			return sessions[i].PID < sessions[j].PID
		}
		return sessions[i].SessionID < sessions[j].SessionID
	})
	out.Sessions = sessions
	return out
}

func (m *Manager) auditBypassLocked(until time.Time, ttl time.Duration) {
	if m.logger == nil {
		m.storeBypassLocked(until)
		return
	}
	m.storeBypassLocked(until)
	_ = m.logger.Write(eventlog.Event{
		EventID:  fmt.Sprintf("root-session-bypass-%d", m.now().UnixNano()),
		Category: "root_session",
		Severity: "high",
		Action:   "root_session_bypass_enabled",
		Decision: "allow",
		RuleID:   "root-session-bypass",
		Subject:  map[string]any{"mode": m.cfg.Mode},
		Evidence: map[string]any{"bypass_until": until, "ttl_sec": int(ttl / time.Second)},
	})
}

func (m *Manager) bypassUntilLocked() time.Time {
	return m.bypassAt
}

func (m *Manager) storeBypassLocked(until time.Time) {
	m.bypassAt = until
}

func (m *Manager) scanLocked() error {
	now := m.now()
	procs, err := m.listProc()
	if err != nil {
		return err
	}
	seen := make(map[string]Process, len(procs))
	for _, proc := range procs {
		class := classifyProcess(m.cfg, proc)
		if class == ClassSystem {
			continue
		}
		sid := sessionID(proc)
		seen[sid] = proc
		s, ok := m.sessions[sid]
		if !ok {
			s = &sessionState{Session: Session{
				SessionID:   sid,
				Class:       class,
				State:       StateObserved,
				PID:         proc.PID,
				PPID:        proc.PPID,
				Name:        proc.Name,
				Path:        proc.Path,
				Cmdline:     proc.Cmdline,
				TTY:         proc.TTY,
				FirstSeenAt: now,
				LastSeenAt:  now,
				LastAction:  "observed",
			}}
			m.sessions[sid] = s
			m.auditLocked("root_session_observed", "root-session-observed", "medium", "alert", s, map[string]any{
				"class": class,
			})
		}
		s.Class = class
		s.PID = proc.PID
		s.PPID = proc.PPID
		s.Name = proc.Name
		s.Path = proc.Path
		s.Cmdline = proc.Cmdline
		s.TTY = proc.TTY
		s.LastSeenAt = now
		if s.State == StateObserved {
			m.issueChallengeLocked(s, now, "scan")
		} else if s.State == StateValid && now.Sub(s.ValidatedAt) >= m.cfg.ChallengeTTL {
			m.issueChallengeLocked(s, now, "renew")
		} else if s.State == StateChallenged && now.After(s.ChallengeBy) {
			s.State = StateGrace
			s.GraceUntil = now.Add(m.cfg.GracePeriod)
			s.LastAction = "grace"
			m.auditLocked("root_session_grace", "root-session-grace", "medium", "alert", s, map[string]any{
				"grace_until": s.GraceUntil,
			})
		} else if s.State == StateGrace && now.After(s.GraceUntil) {
			s.State = StateExpired
			s.LastAction = "expired"
			m.auditLocked("root_session_expired", "root-session-expired", "high", "alert", s, nil)
			m.enforceLocked(s, now)
		}
	}
	for sid := range m.sessions {
		if _, ok := seen[sid]; !ok {
			delete(m.sessions, sid)
		}
	}
	if m.bypassAt.Before(now) {
		m.bypassAt = time.Time{}
		_ = m.saveStateLocked()
	}
	return nil
}

func (m *Manager) issueChallengeLocked(s *sessionState, now time.Time, reason string) Challenge {
	ch := Challenge{
		SessionID: s.SessionID,
		Class:     s.Class,
		PID:       s.PID,
		TTY:       s.TTY,
		Nonce:     randomHex(16),
		Deadline:  now.Add(m.cfg.ChallengeTTL),
		IssuedAt:  now,
	}
	s.State = StateChallenged
	s.ChallengeAt = ch.IssuedAt
	s.ChallengeBy = ch.Deadline
	s.GraceUntil = time.Time{}
	s.LastAction = "challenged"
	s.LastError = ""
	s.nonce = ch.Nonce
	m.auditLocked("root_session_challenged", "root-session-challenge", "medium", "alert", s, map[string]any{
		"reason":   reason,
		"deadline": ch.Deadline,
	})
	return ch
}

func (m *Manager) enforceLocked(s *sessionState, now time.Time) {
	if !m.shouldEnforceLocked(s.Class) {
		return
	}
	if until := m.bypassUntilLocked(); until.After(now) {
		s.LastAction = "bypass_skip"
		m.auditLocked("root_session_enforce_skipped", "root-session-bypass-active", "high", "allow", s, map[string]any{
			"bypass_until": until,
		})
		return
	}
	if s.PID <= 1 {
		s.LastAction = "enforce_skip"
		s.LastError = "pid is not enforceable"
		m.auditLocked("root_session_enforce_skipped", "root-session-not-enforceable", "high", "allow", s, map[string]any{
			"error": s.LastError,
		})
		return
	}
	if err := m.killProc(s.PID); err != nil {
		s.LastAction = "enforce_failed"
		s.LastError = err.Error()
		m.auditLocked("root_session_enforce_failed", "root-session-enforce", "critical", "block", s, map[string]any{
			"error": err.Error(),
		})
		return
	}
	s.LastAction = "enforced"
	s.LastEnforcedAt = now
	s.LastError = ""
	m.auditLocked("root_session_enforced", "root-session-enforce", "critical", "block", s, nil)
}

func (m *Manager) shouldEnforceLocked(class string) bool {
	switch m.cfg.Mode {
	case ModeEnforceAdmin:
		return class == ClassAdmin || class == ClassUnknown
	case ModeEnforceTooling:
		return class == ClassAdmin || class == ClassTooling || class == ClassUnknown
	default:
		return false
	}
}

func (m *Manager) auditLocked(action, ruleID, severity, decision string, s *sessionState, evidence map[string]any) {
	if m.logger == nil || s == nil {
		return
	}
	subject := map[string]any{
		"session_id": s.SessionID,
		"class":      s.Class,
		"pid":        s.PID,
		"ppid":       s.PPID,
		"name":       s.Name,
		"tty":        s.TTY,
	}
	if evidence == nil {
		evidence = map[string]any{}
	}
	if s.ChallengeBy.After(time.Time{}) {
		evidence["deadline"] = s.ChallengeBy
	}
	_ = m.logger.Write(eventlog.Event{
		EventID:  fmt.Sprintf("root-session-%s-%d", action, m.now().UnixNano()),
		Category: "root_session",
		Severity: severity,
		Subject:  subject,
		Action:   action,
		Decision: decision,
		RuleID:   ruleID,
		Evidence: evidence,
	})
}

func (m *Manager) findByPIDLocked(pid int) (*sessionState, error) {
	var found *sessionState
	for sid, s := range m.sessions {
		if sid == "__bypass__" {
			continue
		}
		if s.PID == pid {
			if found == nil || s.LastSeenAt.After(found.LastSeenAt) {
				found = s
			}
		}
	}
	if found == nil {
		return nil, fmt.Errorf("root session pid %d not found", pid)
	}
	return found, nil
}

func classifyProcess(cfg Config, proc Process) string {
	name := strings.ToLower(strings.TrimSpace(proc.Name))
	base := strings.ToLower(strings.TrimSpace(filepath.Base(proc.Path)))
	if name == "" {
		name = base
	}
	if inSet(name, cfg.SystemNames) || inSet(base, cfg.SystemNames) {
		return ClassSystem
	}
	if proc.TTY != "" && (inSet(name, cfg.ShellNames) || inSet(base, cfg.ShellNames)) {
		return ClassAdmin
	}
	if proc.TTY != "" && (inSet(name, cfg.ToolingNames) || inSet(base, cfg.ToolingNames)) {
		return ClassTooling
	}
	if proc.TTY == "" && trustedServiceProcess(cfg, proc) {
		return ClassSystem
	}
	return ClassUnknown
}

func trustedServiceProcess(cfg Config, proc Process) bool {
	if inSet(proc.Name, cfg.SystemNames) || inSet(filepath.Base(proc.Path), cfg.SystemNames) {
		return true
	}
	if kernelThreadProcess(proc) {
		return true
	}
	unit := strings.TrimSpace(proc.ServiceUnit)
	switch {
	case strings.HasSuffix(unit, ".service"),
		strings.HasSuffix(unit, ".socket"),
		strings.HasSuffix(unit, ".mount"),
		strings.HasSuffix(unit, ".timer"),
		strings.HasSuffix(unit, ".path"),
		unit == "init.scope":
		return true
	}
	cgroup := strings.TrimSpace(proc.Cgroup)
	switch {
	case strings.Contains(cgroup, "/system.slice/"),
		strings.Contains(cgroup, "/init.scope"):
		return true
	}
	return false
}

func kernelThreadProcess(proc Process) bool {
	// v0.9: Hardened — PPID MUST be 2 (kthreadd) for kernel threads.
	// PPID 0 or 1 is no longer accepted, as these can be reached by
	// user processes (reparenting to init after parent death).
	if proc.PPID != 2 {
		return false
	}
	if strings.TrimSpace(proc.TTY) != "" {
		return false
	}
	if strings.TrimSpace(proc.Path) != "" {
		return false
	}
	if strings.TrimSpace(proc.Cmdline) != "" {
		return false
	}
	return true
}

func inSet(v string, list []string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	for _, item := range list {
		if v == strings.ToLower(strings.TrimSpace(item)) {
			return true
		}
	}
	return false
}

func sessionID(proc Process) string {
	start := proc.StartTicks
	if start == "" {
		start = "0"
	}
	return fmt.Sprintf("%d:%s", proc.PID, start)
}

func ComputeResponse(secret []byte, sessionID, tty string, pid int, deadline time.Time, nonce string) string {
	mac := hmac.New(sha256.New, secret)
	fmt.Fprintf(mac, "%s\n%s\n%d\n%s\n%s", sessionID, tty, pid, deadline.UTC().Format(time.RFC3339Nano), nonce)
	return hex.EncodeToString(mac.Sum(nil))
}

func randomHex(n int) string {
	if n <= 0 {
		n = 16
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func killPID(pid int) error {
	if pid <= 1 {
		return fmt.Errorf("pid %d is not enforceable", pid)
	}
	return syscall.Kill(pid, syscall.SIGKILL)
}

func ListRootProcesses() ([]Process, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	out := make([]Process, 0, 16)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		proc, err := readProcess(pid)
		if err != nil {
			continue
		}
		if proc.EUID == 0 {
			out = append(out, proc)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out, nil
}

func readProcess(pid int) (Process, error) {
	procDir := filepath.Join("/proc", strconv.Itoa(pid))
	statusRaw, err := os.ReadFile(filepath.Join(procDir, "status"))
	if err != nil {
		return Process{}, err
	}
	status := parseStatus(string(statusRaw))
	euid, _ := strconv.Atoi(fieldAt(status["Uid"], 1))
	ppid, _ := strconv.Atoi(strings.TrimSpace(status["PPid"]))
	name := strings.TrimSpace(status["Name"])
	cmdlineRaw, _ := os.ReadFile(filepath.Join(procDir, "cmdline"))
	cmdline := strings.ReplaceAll(strings.TrimRight(string(cmdlineRaw), "\x00"), "\x00", " ")
	path, _ := os.Readlink(filepath.Join(procDir, "exe"))
	tty := ttyFromProc(procDir)
	cgroupRaw, _ := os.ReadFile(filepath.Join(procDir, "cgroup"))
	cgroup := string(cgroupRaw)
	statRaw, _ := os.ReadFile(filepath.Join(procDir, "stat"))
	return Process{
		PID:         pid,
		PPID:        ppid,
		EUID:        euid,
		Name:        name,
		Path:        path,
		Cmdline:     cmdline,
		TTY:         tty,
		Cgroup:      cgroup,
		ServiceUnit: serviceUnitFromCgroup(cgroup),
		StartTicks:  procutil.StartTicksFromStat(string(statRaw)),
	}, nil
}

func parseStatus(raw string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		out[strings.TrimSpace(key)] = strings.TrimSpace(val)
	}
	return out
}

func fieldAt(s string, idx int) string {
	fields := strings.Fields(strings.TrimSpace(s))
	if idx < 0 || idx >= len(fields) {
		return ""
	}
	return fields[idx]
}

func ttyFromProc(procDir string) string {
	if target, err := os.Readlink(filepath.Join(procDir, "fd", "0")); err == nil {
		if strings.HasPrefix(target, "/dev/pts/") || strings.HasPrefix(target, "/dev/tty") {
			return target
		}
	}
	return ""
}

func serviceUnitFromCgroup(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		_, path, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		for _, segment := range strings.Split(path, "/") {
			segment = strings.TrimSpace(segment)
			switch {
			case strings.HasSuffix(segment, ".service"),
				strings.HasSuffix(segment, ".socket"),
				strings.HasSuffix(segment, ".mount"),
				strings.HasSuffix(segment, ".timer"),
				strings.HasSuffix(segment, ".path"),
				strings.HasSuffix(segment, ".scope"):
				return segment
			}
		}
	}
	return ""
}

func (m *Manager) loadStateLocked() error {
	if strings.TrimSpace(m.cfg.StatePath) == "" {
		return nil
	}
	raw, err := os.ReadFile(m.cfg.StatePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var st persistedState
	if err := json.Unmarshal(raw, &st); err != nil {
		return err
	}
	if st.BypassUntil.After(m.now()) {
		m.bypassAt = st.BypassUntil
	}
	return nil
}

func (m *Manager) saveStateLocked() error {
	if strings.TrimSpace(m.cfg.StatePath) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(m.cfg.StatePath), 0o750); err != nil {
		return err
	}
	st := persistedState{}
	if m.bypassAt.After(m.now()) {
		st.BypassUntil = m.bypassAt
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := m.cfg.StatePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, m.cfg.StatePath)
}
