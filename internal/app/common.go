package app

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"edr/internal/bpf"
	"edr/internal/control"
	iruntime "edr/internal/runtime"
)

var (
	CachedHostname string
	CachedUID      int
	CachedBootID   string
)

func CacheRuntimeVars() {
	if host, err := os.Hostname(); err == nil {
		CachedHostname = host
	}
	CachedUID = os.Getuid()
	if raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		CachedBootID = strings.TrimSpace(string(raw))
	}
}

func ValidateConfigPaths(cfg iruntime.Config) error {
	for _, p := range []string{
		cfg.ArtifactDir,
		filepath.Dir(cfg.EventPath),
		filepath.Dir(cfg.ResponsePath),
		filepath.Dir(cfg.SocketPath),
		filepath.Dir(cfg.PolicyPath),
		filepath.Dir(cfg.BaselinePath),
		filepath.Dir(cfg.Integrity.KeyPath),
		filepath.Dir(cfg.Suppression.StatePath),
		filepath.Dir(cfg.Transport.SensorSocket),
		filepath.Dir(cfg.Transport.OrchestratorSocket),
		filepath.Dir(cfg.Transport.EnforcerSocket),
	} {
		if p == "" || p == "." {
			continue
		}
		if err := control.ValidateBaseNotSymlink(p); err != nil {
			return fmt.Errorf("config security: %w", err)
		}
	}
	return nil
}

func PrepareSocketPath(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to replace symlink socket path %q", path)
	}
	if st.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace non-socket path %q", path)
	}
	return os.Remove(path)
}

func PrepareRuntimeDir(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := control.ValidateBaseNotSymlink(path); err != nil {
		return fmt.Errorf("runtime dir security: %w", err)
	}
	return os.MkdirAll(path, 0o755)
}

func Fatal(err error) {
	fmt.Fprintln(os.Stderr, "edr:", err)
	os.Exit(1)
}

func StartBPFLoader(cfg iruntime.BPFConfig) (bpf.Loader, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.ObjDir == "" {
		return nil, fmt.Errorf("bpf.enabled is true but obj_dir is empty")
	}
	return nil, fmt.Errorf("bpf loader is not wired in shared app helper; use edr-agent build path for ring0 support")
}

type ResourceTracker struct{}

func NewResourceTracker() *ResourceTracker {
	return &ResourceTracker{}
}

func (rt *ResourceTracker) Snapshot() control.ResourceInfo {
	var r control.ResourceInfo
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	r.RSSMB = float64(m.Sys) / (1024 * 1024)
	return r
}
