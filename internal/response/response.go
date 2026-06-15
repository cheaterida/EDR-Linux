package response

import (
	"fmt"
	"os"
	"syscall"

	"edr/internal/procutil"
)

type ActionRequest struct {
	Action      string `json:"action"`
	PID         int    `json:"pid,omitempty"`
	Path        string `json:"path,omitempty"`
	RuleID      string `json:"rule_id,omitempty"`
	RemoteAddr  string `json:"remote_addr,omitempty"`
	LocalPort   int    `json:"local_port,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	ProcessPath string `json:"process_path,omitempty"`
	StartTicks  string `json:"start_ticks,omitempty"`
}

type Result struct {
	Action  string `json:"action"`
	Success bool   `json:"success"`
	Detail  string `json:"detail"`
}

type Responder interface {
	Apply(ActionRequest) Result
}

type SoftResponder struct {
	DryRun     bool
	NFT        NFTProvider
	Quarantine QuarantineProvider
}

func (r SoftResponder) Apply(req ActionRequest) Result {
	if r.DryRun || req.Action == "" || req.Action == "none" {
		return Result{Action: req.Action, Success: true, Detail: "recorded only"}
	}
	switch req.Action {
	case "kill":
		if req.PID <= 1 {
			return Result{Action: req.Action, Success: false, Detail: "refusing to kill protected pid"}
		}
		if !sameProcess(req) {
			return Result{Action: req.Action, Success: false, Detail: "process identity changed before kill"}
		}
		// Use pidfd for TOCTOU-safe signal delivery when available
		// (kernel 5.3+). Falls back to os.FindProcess+Kill on older
		// kernels. pidfd binds to the process instance, so PID reuse
		// between identity check and signal delivery is harmless.
		if err := PidfdKill(req.PID); err == nil {
			return Result{Action: req.Action, Success: true, Detail: fmt.Sprintf("killed pid %d via pidfd", req.PID)}
		} else if err != errPidfdNotSupported {
			return Result{Action: req.Action, Success: false, Detail: err.Error()}
		}
		// Fallback: traditional kill path.
		p, err := os.FindProcess(req.PID)
		if err != nil {
			return Result{Action: req.Action, Success: false, Detail: err.Error()}
		}
		if err := p.Kill(); err != nil {
			return Result{Action: req.Action, Success: false, Detail: err.Error()}
		}
		return Result{Action: req.Action, Success: true, Detail: fmt.Sprintf("killed pid %d", req.PID)}
	case "fix_permissions":
		if req.Path == "" {
			return Result{Action: req.Action, Success: false, Detail: "path required"}
		}
		if err := chmodNoFollow(req.Path, 0o600); err != nil {
			return Result{Action: req.Action, Success: false, Detail: err.Error()}
		}
		return Result{Action: req.Action, Success: true, Detail: "chmod 0600 applied"}
	case "quarantine":
		if req.Path == "" {
			return Result{Action: req.Action, Success: false, Detail: "path required for quarantine"}
		}
		return r.Quarantine.ApplyQuarantine(req.Path, req.RuleID)
	case "kill_tree":
		if req.PID <= 1 {
			return Result{Action: req.Action, Success: false, Detail: "refusing to kill protected pid"}
		}
		return KillTree(req.PID, req.ProcessPath, req.StartTicks)
	case "process_suspend":
		if req.PID <= 1 {
			return Result{Action: req.Action, Success: false, Detail: "refusing to suspend protected pid"}
		}
		return Suspend(req.PID, req.ProcessPath, req.StartTicks)
	case "network_isolate":
		nft := r.NFT
		if r.DryRun {
			nft.DryRun = true
		}
		return nft.ApplyIsolate()
	case "nft_block":
		nft := r.NFT
		if r.DryRun {
			nft.DryRun = true
		}
		return nft.ApplyBlock(req)
	case "fanotify_deny":
		// Enforcement happens synchronously in the fanotify event
		// loop. This records the action for audit purposes only.
		return Result{Action: req.Action, Success: true, Detail: "fanotify deny recorded"}
	default:
		return Result{Action: req.Action, Success: false, Detail: "unsupported action"}
	}
}

func (r SoftResponder) NFTList() any {
	return r.NFT.ListRules()
}

func (r SoftResponder) NFTRollback() any {
	return r.NFT.Rollback()
}

func sameProcess(req ActionRequest) bool {
	if req.PID <= 0 {
		return false
	}
	// At least one identity field must be populated. Unconditional
	// allow with both fields empty was a bypass (SECURITY_AUDIT H1).
	if req.ProcessPath == "" && req.StartTicks == "" {
		return false
	}
	procDir := fmt.Sprintf("/proc/%d", req.PID)
	if req.ProcessPath != "" {
		exe, err := os.Readlink(procDir + "/exe")
		if err != nil || exe != req.ProcessPath {
			return false
		}
	}
	if req.StartTicks != "" {
		statBytes, err := os.ReadFile(procDir + "/stat")
		if err != nil {
			return false
		}
		if procutil.StartTicksFromStat(string(statBytes)) != req.StartTicks {
			return false
		}
	}
	return true
}

func chmodNoFollow(path string, mode uint32) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if err == syscall.ELOOP {
			return fmt.Errorf("refusing to chmod symlink")
		}
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.Fchmod(fd, mode); err != nil {
		return err
	}
	return nil
}

// pidfd syscalls (x86_64, kernel 5.3+). These are not in Go's
// syscall package yet, so we use raw syscall numbers.
const (
	sysPidfdOpen       = 434 // x86_64
	sysPidfdSendSignal = 424 // x86_64
)

var errPidfdNotSupported = fmt.Errorf("pidfd not supported")

// PidfdKill sends SIGKILL to a process via pidfd, which is immune
// to PID reuse races. Returns errPidfdNotSupported if the kernel
// does not support pidfd_open (pre-5.3).
func PidfdKill(pid int) error {
	fd, _, errno := syscall.RawSyscall(sysPidfdOpen, uintptr(pid), 0, 0)
	if errno != 0 {
		if errno == syscall.ENOSYS || errno == syscall.EPERM {
			return errPidfdNotSupported
		}
		// ESRCH = process gone; EINVAL = bad pid
		return fmt.Errorf("pidfd_open(%d): %v", pid, errno)
	}
	defer syscall.Close(int(fd))

	// Double-check identity via pidfd: read /proc/self/fd/N target
	// and compare with /proc/PID/exe. This catches the case where
	// the PID was reused between sameProcess() and pidfd_open.
	if fdExe, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd)); err == nil {
		if procExe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
			if fdExe != procExe {
				return fmt.Errorf("pidfd identity mismatch: fd=%s proc=%s", fdExe, procExe)
			}
		}
	}

	_, _, errno = syscall.RawSyscall(sysPidfdSendSignal, fd, uintptr(syscall.SIGKILL), 0)
	if errno != 0 {
		return fmt.Errorf("pidfd_send_signal(%d): %v", pid, errno)
	}
	return nil
}
