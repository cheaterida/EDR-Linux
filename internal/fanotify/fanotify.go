// Package fanotify provides a synchronous file-access interposition
// provider built on the Linux fanotify(7) API. It intercepts file
// open attempts on configured paths and can deny them before the
// kernel grants access — unlike the inotify-based file watch in the
// procfs collector, which is purely observational.
//
// The provider runs a dedicated goroutine that blocks on reading
// the fanotify fd. Permission events (FAN_OPEN_PERM) must be
// answered synchronously: the provider calls the Handler immediately,
// writes the allow/deny response back to the kernel, then emits an
// audit event. Non-permission events are emitted as informational
// audit events only.
package fanotify

import (
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// Syscall numbers (x86_64).
const (
	cnrFanotifyInit = 300
	cnrFanotifyMark = 301
	catFdCwd = ^uintptr(99) // AT_FDCWD (-100 as uintptr for syscall)
)

// ---------- fanotify_init flags ----------

const (
	FAN_CLASS_CONTENT     = 0x04
	FAN_CLASS_PRE_CONTENT = 0x08
	FAN_CLOEXEC           = 0x01
	FAN_NONBLOCK          = 0x02
	FAN_UNLIMITED_QUEUE   = 0x10
	FAN_UNLIMITED_MARKS   = 0x20
)

// ---------- fanotify_mark flags ----------

const (
	FAN_MARK_ADD    = 0x01
	FAN_MARK_REMOVE = 0x02
	FAN_MARK_MOUNT  = 0x10
)

// ---------- event masks ----------

const (
	FAN_OPEN_PERM      = 0x00010000
	FAN_ACCESS_PERM    = 0x00020000
	FAN_OPEN           = 0x00000020
	FAN_CLOSE_WRITE    = 0x00000008
	FAN_CLOSE_NOWRITE  = 0x00000010
	FAN_MODIFY         = 0x00000002
	FAN_ONDIR          = 0x40000000
	FAN_EVENT_ON_CHILD = 0x08000000
)

// ---------- response values ----------

const (
	FAN_ALLOW = 0x01
	FAN_DENY  = 0x02
	FAN_AUDIT = 0x10
	FAN_NOFD  = -1
)

// fanotifyEventMetadata mirrors the kernel struct. The __aligned_u64
// mask field starts at offset 8, leaving fd at 16 and pid at 20.
// Total size: 24 bytes on x86_64.
type fanotifyEventMetadata struct {
	EventLen    uint32
	Vers        uint8
	Reserved    uint8
	MetadataLen uint16
	Mask        uint64
	Fd          int32
	Pid         int32
}

// fanotifyResponse is written back to the fanotify fd for _PERM events.
type fanotifyResponse struct {
	Fd       int32
	Response uint32
}

// AccessInfo carries the resolved context for a single fanotify
// permission event.
type AccessInfo struct {
	PID     int32
	UID     uint32
	Comm    string
	Exe     string
	Cmdline string
	Path    string
	Mask    uint64
}

// Handler is the policy-decision callback. Return false to deny
// the file access. Called synchronously from the event loop —
// must not block or call back into the Provider.
type Handler interface {
	HandleFileAccess(info AccessInfo) (allow bool, ruleID string)
}

// HandlerFunc wraps a function as a Handler.
type HandlerFunc func(info AccessInfo) (allow bool, ruleID string)

func (f HandlerFunc) HandleFileAccess(info AccessInfo) (allow bool, ruleID string) { return f(info) }

// Logger is the audit-event sink for fanotify events.
type Logger interface {
	Write(ev Event) error
}

// Event is an audit event emitted by the fanotify provider.
type Event struct {
	EventID  string
	Category string
	Severity string
	Subject  map[string]any
	Object   map[string]any
	Action   string
	Decision string
	RuleID   string
}

// Provider manages a fanotify group and its event loop.
type Provider struct {
	mu      sync.Mutex
	fd      int
	paths   []string
	handler Handler
	logger  Logger

	// Performance counters (v0.6 exercise hardening).
	lastLatencyUs int64
	allowCount    uint64
	denyCount     uint64

	// Inode-based file identity for self-protection.
	// Key: inode number (from syscall.Stat_t.Ino)
	// Value: human-readable label for audit logging.
	protectedInodes map[uint64]string
	inodeMu         sync.RWMutex

	stop chan struct{}
	done chan struct{}
}

// New creates a fanotify group, marks the given paths for
// FAN_OPEN_PERM interception, and returns an unstarted Provider.
// Call Start() to begin the event loop.
func New(paths []string, handler Handler, logger Logger) (*Provider, error) {
	flags := FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS
	fd, _, errno := syscall.Syscall(cnrFanotifyInit, uintptr(flags), 0, 0)
	if errno != 0 {
		return nil, fmt.Errorf("fanotify_init: %v", errno)
	}

	p := &Provider{
		fd:      int(fd),
		paths:   append([]string(nil), paths...),
		handler: handler,
		logger:  logger,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}

	for _, path := range p.paths {
		if err := p.mark(path); err != nil {
			syscall.Close(p.fd)
			return nil, fmt.Errorf("fanotify_mark %q: %w", path, err)
		}
	}

	return p, nil
}

// Start begins the blocking event-read loop in a new goroutine.
func (p *Provider) Start() {
	go p.loop()
}

// Stop signals the event loop to exit and waits for it to finish.
// The fanotify fd is closed, which unblocks the read and causes
// the loop to return. All marks are automatically removed by the
// kernel when the fd is closed.
func (p *Provider) Stop() error {
	select {
	case <-p.stop:
		// already stopping
		return nil
	default:
	}
	close(p.stop)
	syscall.Close(p.fd) // unblocks the read in loop()
	<-p.done
	return nil
}

// mark adds fanotify marks for path and all subdirectories recursively
// so that FAN_EVENT_ON_CHILD intercepts file opens at any depth beneath
// the configured watch points. Uses a depth limit of 16 to bound
// traversal, and stops early when the fanotify mark limit is exceeded.
func (p *Provider) mark(root string) error {
	root = filepath.Clean(root)
	var marked int
	var skipped int
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible directories
		}
		if !d.IsDir() {
			return nil
		}
		depth := strings.Count(strings.TrimPrefix(path, root), string(os.PathSeparator))
		if root == path {
			depth = 0
		}
		if depth > 16 {
			skipped++
			return filepath.SkipDir
		}
		if err := p.markOne(path); err != nil {
			// ENOSPC / EPERM on individual subdirs are non-fatal, but
			// we still count them so the caller can observe degraded
			// coverage via stderr.
			skipped++
			return nil
		}
		marked++
		if marked >= 4096 {
			skipped++
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil && marked == 0 {
		return err
	}
	if marked == 0 {
		if err := p.markOne(root); err != nil {
			return err
		}
		marked = 1
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "fanotify: coverage degraded on %q (marked=%d skipped=%d, depth<=16, cap=4096)\n", root, marked, skipped)
	}
	return nil
}

// markOne adds a single fanotify inode mark for a directory with
// FAN_EVENT_ON_CHILD so that open attempts on direct children are
// intercepted.
func (p *Provider) markOne(path string) error {
	pathPtr, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(cnrFanotifyMark,
		uintptr(p.fd),
		uintptr(FAN_MARK_ADD),
		uintptr(FAN_OPEN_PERM|FAN_EVENT_ON_CHILD),
		catFdCwd,
		uintptr(unsafe.Pointer(pathPtr)),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("%v", errno)
	}
	return nil
}

// markFile adds a fanotify inode mark for a single file (not a
// directory). Used for /proc/<pid>/mem and other specific files
// that should not trigger subtree monitoring.
func (p *Provider) markFile(path string) error {
	pathPtr, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(cnrFanotifyMark,
		uintptr(p.fd),
		uintptr(FAN_MARK_ADD),
		uintptr(FAN_OPEN_PERM), // no FAN_EVENT_ON_CHILD for files
		catFdCwd,
		uintptr(unsafe.Pointer(pathPtr)),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("%v", errno)
	}
	return nil
}

// ProtectFile registers a file path for inode-based self-protection.
// It stats the file to obtain its device+inode identity, caches the
// inode, and adds a fanotify mark so future open attempts generate
// permission events. Returns an error if the file cannot be stat'd.
// The description is used in audit log entries.
func (p *Provider) ProtectFile(path, description string) error {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return fmt.Errorf("protect %s: %w", path, err)
	}
	p.inodeMu.Lock()
	if p.protectedInodes == nil {
		p.protectedInodes = make(map[uint64]string)
	}
	p.protectedInodes[st.Ino] = description
	p.inodeMu.Unlock()

	return p.markFile(path)
}

// isProtectedInode checks whether the given file descriptor belongs
// to a protected file. Returns true and the description if protected.
func (p *Provider) isProtectedInode(fd int32) (bool, string) {
	if fd < 0 || fd == FAN_NOFD {
		return false, ""
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(fd), &st); err != nil {
		return false, ""
	}
	p.inodeMu.RLock()
	desc, ok := p.protectedInodes[st.Ino]
	p.inodeMu.RUnlock()
	return ok, desc
}

func (p *Provider) loop() {
	defer close(p.done)

	buf := make([]byte, 8192)
	for {
		select {
		case <-p.stop:
			return
		default:
		}

		// Use select with a 1s timeout so the goroutine can
		// check the stop channel even when no events arrive.
		// A blocking read would hang forever if no file events
		// are generated, preventing clean shutdown.
		fdSet := &syscall.FdSet{}
		fdSet.Bits[p.fd/64] |= 1 << (uint(p.fd) % 64)
		tv := syscall.Timeval{Sec: 1, Usec: 0}
		nready, err := syscall.Select(p.fd+1, fdSet, nil, nil, &tv)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			if err == syscall.EBADF {
				return // fd closed by Stop()
			}
			continue
		}
		if nready <= 0 {
			continue // timeout or spurious wake — re-check stop
		}

		n, err := syscall.Read(p.fd, buf)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EINTR {
				continue
			}
			if err == syscall.EBADF {
				return
			}
			continue
		}
		if n == 0 {
			continue
		}

		p.process(buf[:n])
	}
}

func (p *Provider) process(raw []byte) {
	var meta fanotifyEventMetadata
	for len(raw) >= 24 {
		meta = fanotifyEventMetadata{
			EventLen:    binary.LittleEndian.Uint32(raw[0:4]),
			Vers:        raw[4],
			Reserved:    raw[5],
			MetadataLen: binary.LittleEndian.Uint16(raw[6:8]),
			Mask:        binary.LittleEndian.Uint64(raw[8:16]),
			Fd:          int32(binary.LittleEndian.Uint32(raw[16:20])),
			Pid:         int32(binary.LittleEndian.Uint32(raw[20:24])),
		}

		if meta.EventLen < 24 || int(meta.EventLen) > len(raw) {
			break
		}

		p.handleEvent(meta)
		raw = raw[meta.EventLen:]
	}
}

func (p *Provider) handleEvent(meta fanotifyEventMetadata) {
	path := resolvePath(int(meta.Fd))
	isPerm := meta.Mask&(FAN_OPEN_PERM|FAN_ACCESS_PERM) != 0

	if isPerm {
		// Inode-based self-protection: check BEFORE reading /proc
		// fields. If the target file's inode is in the protected set
		// and the caller is not edr-agent/edrctl, deny immediately.
		// This replaces path-string matching with inode identity,
		// immune to symlink/bind-mount/rename bypasses.
		if protected, desc := p.isProtectedInode(meta.Fd); protected {
			exe := readProcLink(meta.Pid, "exe")
			if exe != "/opt/edr/edr-agent" && exe != "/opt/edr/edrctl" {
				atomic.AddUint64(&p.denyCount, 1)
				_ = writeResponse(p.fd, fanotifyResponse{Fd: meta.Fd, Response: FAN_DENY})
				if meta.Fd != FAN_NOFD {
					syscall.Close(int(meta.Fd))
				}
				p.emitAudit(meta, path, false, "SELF-INODE-"+desc)
				return
			}
			// edr-agent/edrctl: allow immediately without policy evaluation
			_ = writeResponse(p.fd, fanotifyResponse{Fd: meta.Fd, Response: FAN_ALLOW})
			if meta.Fd != FAN_NOFD {
				syscall.Close(int(meta.Fd))
			}
			atomic.AddUint64(&p.allowCount, 1)
			return
		}

		// Fast-path: read only comm first to check critical process
		// list. Avoids 3 unnecessary /proc reads (status, exe, cmdline)
		// for sshd, systemd, and other whitelisted daemons.
		comm := readProcString(meta.Pid, "comm")
		exe := readProcLink(meta.Pid, "exe")

		// Shell bypass is only permitted for interactive shells with
		// a controlling TTY (real admin SSH login). Non-TTY shells
		// (reverse shell, web RCE, curl|bash, cron job) must go
		// through full policy evaluation and can be blocked.
		if isShell(comm) && !hasTTY(meta.Pid) {
			// Fall through to policy evaluation below.
		} else if shouldBypassPermissionCheck(comm, exe, path) {
			_ = writeResponse(p.fd, fanotifyResponse{Fd: meta.Fd, Response: FAN_ALLOW})
			if meta.Fd != FAN_NOFD {
				syscall.Close(int(meta.Fd))
			}
			return
		}

		// Read remaining /proc fields only when policy evaluation is needed.
		info := AccessInfo{
			PID:     meta.Pid,
			UID:     readProcUID(meta.Pid),
			Comm:    comm,
			Exe:     exe,
			Cmdline: readProcCmdline(meta.Pid),
			Path:    path,
			Mask:    meta.Mask,
		}

		// Evaluate policy with panic recovery. If the handler panics,
		// default to ALLOW to avoid blocking the process indefinitely.
		start := time.Now()
		allow, ruleID := p.safeHandleFileAccess(info)
		elapsed := time.Since(start).Microseconds()
		atomic.StoreInt64(&p.lastLatencyUs, elapsed)
		if allow {
			atomic.AddUint64(&p.allowCount, 1)
		} else {
			atomic.AddUint64(&p.denyCount, 1)
		}

		respVal := uint32(FAN_ALLOW)
		if !allow {
			respVal = FAN_DENY
		}
		if err := writeResponse(p.fd, fanotifyResponse{Fd: meta.Fd, Response: respVal}); err != nil {
			// writeResponse failed — the kernel never received a
			// response and the target process will hang indefinitely.
			// Try FAN_ALLOW as a last resort to unblock the process.
			fmt.Fprintf(os.Stderr, "fanotify: %v (pid=%d path=%s), falling back to ALLOW\n", err, meta.Pid, path)
			_ = writeResponse(p.fd, fanotifyResponse{Fd: meta.Fd, Response: FAN_ALLOW})
		}

		p.emitAudit(meta, path, allow, ruleID)
		} else if meta.Mask&(FAN_OPEN|FAN_CLOSE_WRITE|FAN_MODIFY) != 0 {
		// Non-permission events: emit informational only.
		p.emitInfo(meta, path)
	}

	// Close the fd the kernel allocated for this event.
	if meta.Fd != FAN_NOFD {
		syscall.Close(int(meta.Fd))
	}
}

// safeHandleFileAccess wraps handler.HandleFileAccess with panic recovery.
// On panic, defaults to ALLOW to avoid blocking the target process.
func (p *Provider) safeHandleFileAccess(info AccessInfo) (allow bool, ruleID string) {
	allow = true // default to ALLOW on any failure
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "fanotify: handler panic: %v (pid=%d path=%s), defaulting to ALLOW\n", r, info.PID, info.Path)
			allow = true
			ruleID = ""
		}
	}()
	allow, ruleID = p.handler.HandleFileAccess(info)
	return
}

func (p *Provider) emitAudit(meta fanotifyEventMetadata, path string, allowed bool, ruleID string) {
	decision := "allow"
	severity := "low"
	if !allowed {
		decision = "block"
		severity = "high"
	}
	p.logger.Write(Event{
		EventID:  fmt.Sprintf("fanotify-%d-%d", meta.Pid, meta.Mask),
		Category: "file",
		Severity: severity,
		Subject: map[string]any{
			"pid":     meta.Pid,
			"comm":    readProcString(meta.Pid, "comm"),
			"exe":     readProcLink(meta.Pid, "exe"),
			"cmdline": readProcCmdline(meta.Pid),
		},
		Object: map[string]any{
			"path": path,
			"mask": meta.Mask,
		},
		Action:   decision,
		Decision: decision,
		RuleID:   ruleID,
	})
}

func (p *Provider) emitInfo(meta fanotifyEventMetadata, path string) {
	p.logger.Write(Event{
		EventID:  fmt.Sprintf("fanotify-info-%d-%d", meta.Pid, meta.Mask),
		Category: "file",
		Severity: "low",
		Subject: map[string]any{
			"pid":  meta.Pid,
			"comm": readProcString(meta.Pid, "comm"),
		},
		Object: map[string]any{
			"path": path,
			"mask": meta.Mask,
		},
		Action:   "observe",
		Decision: "alert",
		RuleID:   "file-watch",
	})
}

// Perf returns the current fanotify performance snapshot (v0.6).
func (p *Provider) Perf() (latencyUs int64, allow, deny uint64) {
	return atomic.LoadInt64(&p.lastLatencyUs),
		atomic.LoadUint64(&p.allowCount),
		atomic.LoadUint64(&p.denyCount)
}

// ---------- syscall helpers ----------

func resolvePath(fd int) string {
	if fd < 0 {
		return ""
	}
	link, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(link, " (deleted)")
}

func writeResponse(fd int, resp fanotifyResponse) error {
	raw := make([]byte, 8)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(resp.Fd))
	binary.LittleEndian.PutUint32(raw[4:8], resp.Response)
	if _, err := syscall.Write(fd, raw); err != nil {
		return fmt.Errorf("fanotify write response: %w", err)
	}
	return nil
}

func readProcString(pid int32, file string) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/%s", pid, file))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readProcLink(pid int32, file string) string {
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/%s", pid, file))
	if err != nil {
		return ""
	}
	return link
}

func readProcUID(pid int32) uint32 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line)
		// fields: ["Uid:", real, effective, saved, filesystem]
		if len(fields) >= 2 {
			uid, err := strconv.ParseUint(fields[1], 10, 32)
			if err == nil {
				return uint32(uid)
			}
		}
		break
	}
	return 0
}

func shouldBypassPermissionCheck(comm, exe, path string) bool {
	// v0.16: Security-sensitive paths are NEVER bypassed —
	// not even for bash/sshd. This closes the "attacker uses
	// bash shell to write webshells, SSH backdoors, or tamper
	// with WAF config" attack vector.
	if isSecuritySensitivePath(path) {
		return false
	}
	if isCriticalPath(path) {
		return true
	}
	return isCriticalProcessForPath(comm, exe, path)
}

// isCriticalProcess returns true for system daemons whose file opens
// must never be blocked by fanotify. Blocking sshd, systemd, or PAM
// helpers will break SSH and system management.
func isCriticalProcessForPath(comm, exe, path string) bool {
	// Security-sensitive paths: NEVER bypass policy, even for bash/sshd.
	if isSecuritySensitivePath(path) {
		return false
	}

	// EDR self-protection: /opt/edr/ and /etc/edr/ are only writable
	// by edr-agent and edrctl — even root's bash shell is blocked.
	// This check runs BEFORE the critical process list, so bash/sh
	// cannot bypass it. The credential to access these paths is to
	// be the edr-agent or edrctl process itself.
	if strings.HasPrefix(path, "/opt/edr/") || strings.HasPrefix(path, "/etc/edr/") {
		return exe == "/opt/edr/edr-agent" || exe == "/opt/edr/edrctl"
	}

	switch comm {
	case "sshd", "ssh", "systemd", "systemd-logind", "systemd-journal",
		"systemd-udevd", "dbus-daemon", "login", "agetty",
		"polkitd", "accounts-daemon", "sudo", "su",
		"systemd-hostnam", "systemd-resolve", "systemd-network",
		"bash", "sh", "dash", "zsh", "rbash",
		"edr-agent", "edrctl",
		"systemctl", "journalctl", "update-grub", "grub-mkconfig",
		"dpkg", "apt", "apt-get", "python3":
		return true
	}
	return false
}

// isCriticalPath returns true for paths that system services depend on
// for basic operation (SSH config, PAM, user database, key material).
func isCriticalPath(path string) bool {
	for _, prefix := range criticalPathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	// Protect .ssh directories under any home directory
	// (e.g. /root/.ssh/authorized_keys, /home/lcz/.ssh/authorized_keys).
	if strings.Contains(path, "/.ssh/") {
		return true
	}
	return false
}

var criticalPathPrefixes = []string{
	"/etc/ssh/",
	"/etc/pam.d/",
	"/etc/security/",
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/gshadow",
	"/etc/nsswitch.conf",
	"/etc/resolv.conf",
	"/etc/hosts",
	"/etc/hostname",
	"/etc/ssl/",
	"/etc/ca-certificates/",
	"/root/.ssh/",
	"/run/",
	"/var/run/",
	"/dev/pts/",
	"/etc/profile.d/",
	"/etc/bash.bashrc",
	"/etc/environment",
	"/etc/inputrc",
	"/etc/default/",
}

// isSecuritySensitivePath returns true for paths that must NEVER bypass
// fanotify policy evaluation — not even for critical processes like bash
// or sshd. These are the paths attackers target: webshell deployment,
// SSH backdoor injection, WAF config tampering, BPF/kprobe disabling.
//
// v0.16: This closes the attack vector where an attacker who gets a bash
// shell (via ShopPulse RCE) can write to /var/www/edgeops/ or
// /root/.ssh/ without being blocked by fanotify policy rules.
func isSecuritySensitivePath(path string) bool {
	for _, prefix := range securitySensitivePaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

var securitySensitivePaths = []string{
	"/sys/kernel/debug/kprobes", // kprobe global disable
	"/var/www/edgeops/",         // webshell deployment
	"/opt/edgeops/lib/",         // trojan JAR deployment
	"/root/waf-proxy/",          // WAF config tampering
	"/etc/nginx/",               // nginx config hijack
	"/etc/ssh/sshd_config",      // SSH config tampering
}

func readProcCmdline(pid int32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	return strings.ReplaceAll(strings.TrimRight(string(data), "\x00"), "\x00", " ")
}

// isShell returns true if comm is a Unix shell process name.
func isShell(comm string) bool {
	switch comm {
	case "bash", "sh", "dash", "zsh", "rbash", "ksh", "csh", "tcsh":
		return true
	}
	return false
}

// hasTTY checks whether the process has a controlling terminal by
// reading /proc/<pid>/fd/0. Returns true if fd 0 is a TTY device
// (/dev/pts/* or /dev/tty*), indicating an interactive session.
func hasTTY(pid int32) bool {
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/0", pid))
	if err != nil {
		return false
	}
	return strings.HasPrefix(target, "/dev/pts/") ||
		strings.HasPrefix(target, "/dev/tty")
}
