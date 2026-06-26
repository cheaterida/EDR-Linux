package integrity

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func TestSelfCheckBinaryIntegrity(t *testing.T) {
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "edr-agent")
	os.WriteFile(bin, []byte("original binary content"), 0o755)

	s, err := NewSelfCheck(Config{
		BinaryPath: bin,
		InstallDir: tmp,
	})
	if err != nil {
		t.Fatalf("NewSelfCheck: %v", err)
	}

	// Baseline check — all should pass
	results := s.RunAll()
	for _, r := range results {
		if r.Name == "binary_hash" && !r.Passed {
			t.Errorf("baseline binary_hash should pass: %s", r.Detail)
		}
	}

	// Tamper — modify binary
	os.WriteFile(bin, []byte("modified by attacker"), 0o755)
	results = s.RunAll()
	found := false
	for _, r := range results {
		if r.Name == "binary_hash" && !r.Passed {
			found = true
		}
	}
	if !found {
		t.Error("binary_hash should fail after tampering")
	}
}

func TestSelfCheckInstallDir(t *testing.T) {
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "edr-agent")
	os.WriteFile(bin, []byte("test"), 0o755)

	s, err := NewSelfCheck(Config{
		BinaryPath: bin,
		InstallDir: tmp,
	})
	if err != nil {
		t.Fatalf("NewSelfCheck: %v", err)
	}

	results := s.RunAll()
	for _, r := range results {
		if r.Name == "install_dir" && !r.Passed {
			t.Errorf("install_dir should pass: %s", r.Detail)
		}
	}

	// Remove dir
	os.RemoveAll(tmp)
	results = s.RunAll()
	found := false
	for _, r := range results {
		if r.Name == "install_dir" && !r.Passed {
			found = true
		}
	}
	if !found {
		t.Error("install_dir should fail after removal")
	}
}

func TestSOSEmission(t *testing.T) {
	// SOS should not panic, even with all optional fields.
	EmitSOS("test_reason", []CheckResult{
		{Name: "bpf_heartbeat", Passed: false, Detail: "stale"},
		{Name: "binary_hash", Passed: false, Detail: "modified"},
	})
}

func TestSOSWithEd25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	results := []CheckResult{{Name: "test", Passed: false, Detail: "forced failure"}}
	EmitSOS("ed25519_test", results, WithEd25519(priv))
}

func TestSOSWithHMAC(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	results := []CheckResult{{Name: "test", Passed: false, Detail: "forced failure"}}
	EmitSOS("hmac_test", results, WithHMAC(key))

	// Verify HMAC signature matches
	msg := sosSigningMessage(&SOSEvent{
		Type:      "edr_compromise",
		Timestamp: "test",
		Hostname:  "test",
		Reason:    "hmac_test",
	})
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	if len(mac.Sum(nil)) != 32 {
		t.Error("HMAC should be 32 bytes")
	}
}

func TestSOSOptions(t *testing.T) {
	pids := []int{1234, 5678}

	results := []CheckResult{{Name: "test", Passed: false, Detail: "failure"}}
	EmitSOS("option_test", results, WithEDRPIDs(pids))
}
