package lease

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Lease struct {
	LeaseID    string    `json:"lease_id"`
	Target     string    `json:"target"`
	RequestID  string    `json:"request_id"`
	Source     string    `json:"source"`
	Generation uint64    `json:"generation"`
	Priority   int       `json:"priority"`
	AcquiredAt time.Time `json:"acquired_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func Path(runDir, target string) string {
	return filepath.Join(runDir, fmt.Sprintf("%s.restart_lease", target))
}

func Acquire(runDir string, next Lease) (Lease, bool, error) {
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return Lease{}, false, err
	}
	current, err := Read(runDir, next.Target)
	if err == nil && current.ExpiresAt.After(time.Now().UTC()) {
		if current.Priority > next.Priority {
			return current, false, nil
		}
		if current.Priority == next.Priority && current.RequestID != next.RequestID {
			return current, false, nil
		}
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return Lease{}, false, err
	}
	tmp := Path(runDir, next.Target) + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o640); err != nil {
		return Lease{}, false, err
	}
	if err := os.Rename(tmp, Path(runDir, next.Target)); err != nil {
		return Lease{}, false, err
	}
	return next, true, nil
}

func Read(runDir, target string) (Lease, error) {
	var l Lease
	raw, err := os.ReadFile(Path(runDir, target))
	if err != nil {
		return l, err
	}
	if err := json.Unmarshal(raw, &l); err != nil {
		return l, err
	}
	return l, nil
}

func Release(runDir, target, leaseID string) error {
	current, err := Read(runDir, target)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if current.LeaseID != leaseID {
		return fmt.Errorf("lease holder mismatch")
	}
	return os.Remove(Path(runDir, target))
}
