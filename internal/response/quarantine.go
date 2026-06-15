package response

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// QuarantineProvider isolates suspicious files by moving them into a
// quarantine directory and stripping all permissions. All operations
// are fd-based to avoid TOCTOU races.
type QuarantineProvider struct {
	Dir    string
	DryRun bool
}

// QuarantineMeta records the original location of a quarantined file.
type QuarantineMeta struct {
	OriginalPath string    `json:"original_path"`
	QuarantineAt time.Time `json:"quarantine_at"`
	Inode        uint64    `json:"inode"`
	Size         int64     `json:"size"`
	RuleID       string    `json:"rule_id,omitempty"`
}

// ApplyQuarantine moves a file into the quarantine directory with
// zeroed permissions. TOCTOU-safe: opens via O_PATH, then operates
// on the fd.
func (q QuarantineProvider) ApplyQuarantine(path string, ruleID string) Result {
	if q.DryRun {
		return Result{Action: "quarantine", Success: true, Detail: fmt.Sprintf("dry-run: would quarantine %s", path)}
	}

	// Ensure quarantine directory exists
	if err := os.MkdirAll(q.Dir, 0o700); err != nil {
		return Result{Action: "quarantine", Success: false, Detail: fmt.Sprintf("mkdir quarantine dir: %v", err)}
	}

	// Open the file with O_PATH (no content access) and O_NOFOLLOW
	// O_PATH = 010000000 on Linux
	const oPath = 010000000
	fd, err := syscall.Open(path, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if err == syscall.ELOOP {
			return Result{Action: "quarantine", Success: false, Detail: "refusing to quarantine symlink"}
		}
		return Result{Action: "quarantine", Success: false, Detail: fmt.Sprintf("open: %v", err)}
	}
	defer syscall.Close(fd)

	// Get file info via the fd
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return Result{Action: "quarantine", Success: false, Detail: fmt.Sprintf("fstat: %v", err)}
	}

	// Generate quarantine filename: inode + timestamp
	qName := fmt.Sprintf("%d_%d", stat.Ino, time.Now().UnixNano())
	qPath := filepath.Join(q.Dir, qName)

	// Rename into quarantine directory (same filesystem required)
	if err := syscall.Rename(path, qPath); err != nil {
		return Result{Action: "quarantine", Success: false, Detail: fmt.Sprintf("rename: %v", err)}
	}

	// Strip all permissions via fd on the new path
	qfd, err := syscall.Open(qPath, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return Result{Action: "quarantine", Success: false, Detail: fmt.Sprintf("open quarantined file: %v", err)}
	}
	defer syscall.Close(qfd)

	if err := syscall.Fchmod(qfd, 0o000); err != nil {
		return Result{Action: "quarantine", Success: false, Detail: fmt.Sprintf("fchmod: %v", err)}
	}

	// Write metadata sidecar
	meta := QuarantineMeta{
		OriginalPath: path,
		QuarantineAt: time.Now(),
		Inode:        stat.Ino,
		Size:         stat.Size,
		RuleID:       ruleID,
	}
	metaPath := qPath + ".meta"
	metaData, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(metaPath, metaData, 0o600); err != nil {
		return Result{Action: "quarantine", Success: true, Detail: fmt.Sprintf("quarantined to %s (meta write failed: %v)", qPath, err)}
	}

	return Result{Action: "quarantine", Success: true, Detail: fmt.Sprintf("quarantined %s -> %s", path, qPath)}
}

// ListQuarantined returns metadata for all quarantined files.
func (q QuarantineProvider) ListQuarantined() ([]QuarantineMeta, error) {
	entries, err := os.ReadDir(q.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []QuarantineMeta
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) == ".meta" {
			continue
		}
		metaPath := filepath.Join(q.Dir, e.Name()+".meta")
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var meta QuarantineMeta
		if err := json.Unmarshal(data, &meta); err != nil {
			continue
		}
		out = append(out, meta)
	}
	return out, nil
}

// Restore moves a quarantined file back to its original location.
func (q QuarantineProvider) Restore(originalPath string) Result {
	entries, err := os.ReadDir(q.Dir)
	if err != nil {
		return Result{Action: "quarantine_restore", Success: false, Detail: err.Error()}
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) == ".meta" {
			continue
		}
		metaPath := filepath.Join(q.Dir, e.Name()+".meta")
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var meta QuarantineMeta
		if err := json.Unmarshal(data, &meta); err != nil {
			continue
		}
		if meta.OriginalPath != originalPath {
			continue
		}
		qPath := filepath.Join(q.Dir, e.Name())
		// Restore permissions before move
		if err := os.Chmod(qPath, 0o600); err != nil {
			return Result{Action: "quarantine_restore", Success: false, Detail: fmt.Sprintf("chmod: %v", err)}
		}
		if err := os.Rename(qPath, originalPath); err != nil {
			return Result{Action: "quarantine_restore", Success: false, Detail: fmt.Sprintf("rename: %v", err)}
		}
		// Clean up meta file
		os.Remove(metaPath)
		return Result{Action: "quarantine_restore", Success: true, Detail: fmt.Sprintf("restored %s", originalPath)}
	}
	return Result{Action: "quarantine_restore", Success: false, Detail: fmt.Sprintf("no quarantined file found for %s", originalPath)}
}
