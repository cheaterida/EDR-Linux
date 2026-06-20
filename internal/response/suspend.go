package response

import (
	"fmt"
	"os"
	"sync"
	"syscall"
)

var (
	suspendedMu sync.Mutex
	suspended   = map[int]string{} // pid -> process path at freeze time
)

// Suspend sends SIGSTOP to a process via pidfd, freezing it for
// forensic analysis. The process is tracked for later Resume.
func Suspend(pid int, processPath, startTicks string) Result {
	if pid <= 1 {
		return Result{Action: "process_suspend", Success: false, Detail: "refusing to suspend protected pid"}
	}
	// Identity check
	if processPath != "" || startTicks != "" {
		req := ActionRequest{PID: pid, ProcessPath: processPath, StartTicks: startTicks}
		if !sameProcess(req) {
			return Result{Action: "process_suspend", Success: false, Detail: "process identity changed"}
		}
	}

	// Send SIGSTOP via pidfd
	if err := pidfdSignal(pid, syscall.SIGSTOP); err != nil && err != errPidfdNotSupported {
		return Result{Action: "process_suspend", Success: false, Detail: err.Error()}
	} else if err == errPidfdNotSupported {
		// Fallback to regular signal
		p, err := findProcess(pid)
		if err != nil {
			return Result{Action: "process_suspend", Success: false, Detail: err.Error()}
		}
		if err := p.Signal(syscall.SIGSTOP); err != nil {
			return Result{Action: "process_suspend", Success: false, Detail: err.Error()}
		}
	}

	suspendedMu.Lock()
	suspended[pid] = processPath
	suspendedMu.Unlock()

	return Result{Action: "process_suspend", Success: true, Detail: fmt.Sprintf("suspended pid %d", pid)}
}

// Resume sends SIGCONT to a previously suspended process.
func Resume(pid int) Result {
	if err := pidfdSignal(pid, syscall.SIGCONT); err != nil && err != errPidfdNotSupported {
		return Result{Action: "process_resume", Success: false, Detail: err.Error()}
	} else if err == errPidfdNotSupported {
		p, err := findProcess(pid)
		if err != nil {
			return Result{Action: "process_resume", Success: false, Detail: err.Error()}
		}
		if err := p.Signal(syscall.SIGCONT); err != nil {
			return Result{Action: "process_resume", Success: false, Detail: err.Error()}
		}
	}

	suspendedMu.Lock()
	delete(suspended, pid)
	suspendedMu.Unlock()

	return Result{Action: "process_resume", Success: true, Detail: fmt.Sprintf("resumed pid %d", pid)}
}

// SuspendedPIDs returns a snapshot of all frozen PIDs and their paths.
func SuspendedPIDs() map[int]string {
	suspendedMu.Lock()
	defer suspendedMu.Unlock()
	out := make(map[int]string, len(suspended))
	for pid, path := range suspended {
		out[pid] = path
	}
	return out
}

// pidfdSignal sends an arbitrary signal to a process via pidfd.
func pidfdSignal(pid int, sig syscall.Signal) error {
	fd, _, errno := syscall.RawSyscall(sysPidfdOpen, uintptr(pid), 0, 0)
	if errno != 0 {
		if errno == syscall.ENOSYS || errno == syscall.EPERM {
			return errPidfdNotSupported
		}
		return fmt.Errorf("pidfd_open(%d): %v", pid, errno)
	}
	defer syscall.Close(int(fd))

	_, _, errno = syscall.RawSyscall(sysPidfdSendSignal, fd, uintptr(sig), 0)
	if errno != 0 {
		return fmt.Errorf("pidfd_send_signal(%d, %d): %v", pid, sig, errno)
	}
	return nil
}

func findProcess(pid int) (*os.Process, error) {
	return os.FindProcess(pid)
}
