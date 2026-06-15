package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeConfigFile is a small helper: serialize cfg as JSON, write
// it into a tempdir, and return the file path. The file is
// cleaned up automatically when the test ends.
func writeConfigFile(t *testing.T, cfg config) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "agent.json")
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestLoadConfig_MissingFileUsesDefaults(t *testing.T) {
	cfg, err := loadConfig("/nonexistent/path/does/not/matter.json")
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.BPF.Enabled {
		t.Errorf("BPF default: want enabled=false, got true")
	}
	if cfg.IntervalSec != 1 {
		t.Errorf("IntervalSec default: want 1, got %d", cfg.IntervalSec)
	}
}

func TestLoadConfig_BPFSectionParsed(t *testing.T) {
	cfg, err := loadConfig(writeConfigFile(t, config{
		PolicyPath:   "configs/policy.json",
		BaselinePath: "configs/baseline.json",
		EventPath:    "var/events.jsonl",
		ResponsePath: "var/responses.jsonl",
		ArtifactDir:  "var/forensics",
		SocketPath:   "var/run/edr-agent.sock",
		IntervalSec:  10,
		BPF: bpfConfig{
			Enabled:      true,
			ObjDir:       "/opt/edr/bpf",
			RingbufPages: 512,
			RingbufPath:  "/sys/fs/bpf/edr/events",
		},
	}))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !cfg.BPF.Enabled {
		t.Errorf("BPF.Enabled: want true, got false")
	}
	if cfg.BPF.ObjDir != "/opt/edr/bpf" {
		t.Errorf("ObjDir: want %q, got %q", "/opt/edr/bpf", cfg.BPF.ObjDir)
	}
	if cfg.BPF.RingbufPages != 512 {
		t.Errorf("RingbufPages: want 512, got %d", cfg.BPF.RingbufPages)
	}
	if cfg.BPF.RingbufPath != "/sys/fs/bpf/edr/events" {
		t.Errorf("RingbufPath: got %q", cfg.BPF.RingbufPath)
	}
}

func TestLoadConfig_RejectsUnknownField(t *testing.T) {
	// R-C2: DisallowUnknownFields must reject typos like
	// "bpf_enbled" so misconfigured deployments fail loudly
	// at startup instead of silently dropping the ring0
	// surface.
	p := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(p, []byte(`{"bpf_enbled": true}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := loadConfig(p); err == nil {
		t.Fatal("expected DisallowUnknownFields to reject bpf_enbled, got nil")
	}
}

func TestStartBPFLoader_DisabledReturnsNil(t *testing.T) {
	l, err := startBPFLoader(bpfConfig{Enabled: false})
	if err != nil {
		t.Errorf("disabled loader should be a no-op, got err: %v", err)
	}
	if l != nil {
		t.Errorf("disabled loader should return nil, got %T", l)
	}
}

func TestStartBPFLoader_EnabledWithoutObjDirIsFatal(t *testing.T) {
	_, err := startBPFLoader(bpfConfig{Enabled: true, ObjDir: ""})
	if err == nil {
		t.Fatal("enabled loader with empty obj_dir must fail (R-C1)")
	}
}

func TestStartBPFLoader_EnabledIsExplicitlyNotWired(t *testing.T) {
	// v0.2 step 4c lands the real libbpf loader. Until then,
	// bpf.enabled=true must surface a clear error rather than
	// silently behaving like procfs-only.
	_, err := startBPFLoader(bpfConfig{Enabled: true, ObjDir: "/tmp/bpf"})
	if err == nil {
		t.Fatal("enabled loader must error until libbpf wiring lands")
	}
}
